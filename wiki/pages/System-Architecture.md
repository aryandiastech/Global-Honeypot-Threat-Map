# System Architecture

The Global Honeypot Threat Map employs an event-driven, multi-cloud layer architecture spanning the AWS Serverless stack and containerized Fargate clusters.

## 1. Interaction Layer (AWS ECS Fargate)
- We host the honeypots (**Cowrie**) in Fargate Spot instances on explicit AWS Regions (e.g., `ap-south-1` and `us-east-1`).
- Fargate inherently scales without the administrative overhead of configuring Elastic Cloud Compute (EC2) boundaries. 

## 2. Ingestion & Logging (AWS S3 & CloudWatch)
- The Cowrie nodes utilize an internal `log_shipper.py` to buffer malicious interactions into AWS S3 storage.
- Using AWS standard Identity rules (Least-Privilege task execution roles), the shippers seamlessly trigger the processing cascade.

## 3. Data Processing (Lambda & DynamoDB)
- The Serverless Application Model (SAM) encapsulates Data Normalization via `ingest_lambda`. 
- S3 bucket creations implicitly queue lambda invocations to structure the raw payload into a searchable NoSQL DynamoDB pattern.
- Asynchronous DynamoDB Event Streams dispatch the data to further modules (like our IP Reputation engine `enrich_lambda`).

## 4. Machine Learning Module
- Unsupervised learning happens securely inside an isolated Lambda triggered chronologically by Amazon EventBridge.
- It scrapes recent DynamoDB entries, tags "clusters", and updates the database, entirely circumventing the requirement for costly GPU-instances.

## 5. Web Interface (React & Mapbox)
- Static assets deploy freely on platforms like Vercel or AWS Amplify.
- Users connect directly to the Public API Gateway pulling cached NoSQL telemetry to draw 3-Dimensional attack maps.
