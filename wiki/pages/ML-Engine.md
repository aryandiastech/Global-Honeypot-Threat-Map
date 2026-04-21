# Machine Learning Engine

This page documents the Unsupervised Learning component of the Global Honeypot Threat Map, which groups similar hacking events together.

## Objective
Detect coordinated distributed attacks ("botnets") versus random isolated noise.

## Model Chosen: DBSCAN (Density-Based Spatial Clustering of Applications with Noise)
Why DBSCAN over K-Means?
- We do not know how many "botnets" (clusters) to expect in advance.
- DBSCAN excels at finding dense clusters and heavily penalizes random single scanners, classifying them accurately as "noise". K-Means forces every point into a cluster.

## Feature Extraction Matrix
The current model uses a lightweight, 2-dimensional feature array:
1. **Time Feature**: Extracted from the attack timestamp, transformed into an hourly float `[0.0 - 1.0]`. Groups attacks occurring in the same temporal band.
2. **IP Identity Hash**: A deterministic SHA-256 slice scaled to `[0.0 - 1.0]`. Identical IPs stack up in the exact same spatial dimension.
*(Note: Future iterations should include credential pairs and executed shell commands).*

## AWS Deployment Architecture
Operating Machine Learning engines continuously in the cloud can quickly drain Free Tier credits. 
To bypass this limitation, we deploy the model entirely Serverless:
1. **AWS Lambda (`ClusterFunction`)**: Configured via AWS SAM to package `scikit-learn` and `numpy`.
2. **Amazon EventBridge**: Triggers the lambda execution regularly via a Schedule Rate expression (e.g., `rate(30 minutes)`).
3. **Execution**: The Lambda scans the latest 1,000 DynamoDB events, runs the offline DBSCAN clustering array, calculates the numeric label, and iterates over the items to `UpdateItem` with the `cluster_id`. 
4. The React Mapbox Frontend natively pulls this `cluster_id` from the Read API.
