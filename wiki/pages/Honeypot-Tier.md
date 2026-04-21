# Honeypot Tier Architecture

This page outlines the honeypot layer of our Global Threat Map.

## Technology Stack
- **Honeypot Software**: [Cowrie SSH/Telnet Honeypot](https://github.com/cowrie/cowrie)
- **Containerization**: Docker
- **Deployment**: AWS ECS (Elastic Container Service) on Fargate Spot

## Design Decisions
We chose Fargate to minimize server maintenance and eliminate the need for patching base EC2 instances, which is crucial for a security-related deployment. We utilize **Fargate Spot** to keep costs severely low (in many cases falling within the AWS Free Tier limitations when using 0.25 vCPU and 0.5 GB RAM).

## The Log Shipper Daemon
To adhere to best-practice separation of concerns without spinning up a heavy memory-intensive sidecar (like FluentBit), we incorporated a lightweight, custom Python script `log_shipper.py` directly into the Cowrie container via `start.sh`.

- It wakes up every 60 seconds.
- It tails `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`.
- It dynamically ships the new JSONL events directly to our central S3 Bucket using temporary STS credentials provided by the ECS Task Role.

## Infrastructure as Code
Deployments are managed using CloudFormation. The configuration file `fargate-deploy.yaml` specifies:
- The ECS Cluster configuration
- Our Task Definition (RAM/CPU boundaries)
- IAM roles enforcing strict Least-Privilege access (`s3:PutObject` only on our specific log bucket)
