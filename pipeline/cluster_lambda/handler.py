import os
import boto3
import hashlib
from datetime import datetime
import numpy as np
from sklearn.cluster import DBSCAN

# Initialize Boto3 client
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get("EVENTS_TABLE_NAME")

def _hour_feature(isoish: str) -> float:
    if not isoish:
        return 0.0
    try:
        dt = datetime.fromisoformat(isoish.replace("Z", "+00:00"))
        return float(dt.hour) / 23.0
    except ValueError:
        return 0.0

def _ip_feature(ip: str) -> float:
    digest = hashlib.sha256(ip.encode("utf-8", errors="replace")).digest()
    return int.from_bytes(digest[:4], "big", signed=False) / float(0xFFFFFFFF)

def lambda_handler(event, context):
    if not table_name:
        print("EVENTS_TABLE_NAME not set.")
        return

    table = dynamodb.Table(table_name)
    
    # Simple scan up to 1000 items to cluster (in a real app, use secondary index by received_at)
    response = table.scan(Limit=1000)
    items = response.get('Items', [])
    
    if len(items) < 2:
        print("Not enough items to cluster.")
        return

    # Extract features
    valid_items = []
    features = []
    
    for item in items:
        # Require src_ip and received_at to cluster effectively
        if 'src_ip' in item and 'received_at' in item:
            valid_items.append(item)
            features.append([
                _ip_feature(item['src_ip']), 
                _hour_feature(item['received_at'])
            ])

    if len(valid_items) < 2:
        return

    # Run DBSCAN
    feats_array = np.array(features, dtype=np.float64)
    model = DBSCAN(eps=0.12, min_samples=2)
    labels = model.fit_predict(feats_array)
    
    updates = 0
    # Update DynamoDB with cluster_id
    # Note: AWS limits 1 update per request, we do simple looped updates
    for idx, label in enumerate(labels.tolist()):
        cluster_id = int(label)
        item = valid_items[idx]
        
        # Avoid unnecessary DB writes if cluster_id is already the same
        current_cluster = item.get('cluster_id')
        # DynamoDB uses decimal/int, so compare numeric values
        if current_cluster is None or int(current_cluster) != cluster_id:
            table.update_item(
                Key={'event_id': item['event_id']},
                UpdateExpression="set cluster_id = :val",
                ExpressionAttributeValues={':val': cluster_id}
            )
            updates += 1

    print(f"Clustered {len(valid_items)} items. Clusters generated (including noise): {len(set(labels))}. DB updates made: {updates}")
    return {"status": "success", "updated": updates}
