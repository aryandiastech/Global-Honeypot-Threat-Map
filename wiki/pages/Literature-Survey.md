# Literature Survey

This page summarizes key background relevant to honeypots, serverless pipelines, and unsupervised clustering for attack grouping.

## Honeypots and data capture

- Cowrie documentation (Docker usage, config mounting, ports) is a primary implementation reference.
  - `https://docs.cowrie.org/en/latest/docker/README.html`

## Serverless processing (S3 → Lambda)

- AWS describes processing S3 event notifications with Lambda, including asynchronous invocation and pitfalls like trigger loops.
  - `https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html`

## Serverless permissions (SAM templates)

- SAM policy templates simplify least-privilege permissions for common patterns.
  - `https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-policy-templates.html`

## Unsupervised clustering for botnets / attacks

DBSCAN is commonly used in security contexts because it can discover clusters without a predefined \(K\) and label noise.

Suggested starting references:

- Behaviour-based clustering of IoT botnets (DBSCAN) (MDPI)  
  `https://www.mdpi.com/1999-5903/14/1/6`
- Using honeypots to model botnet attacks (survey-style context) (PMC)  
  `https://pmc.ncbi.nlm.nih.gov/articles/PMC9264116/`

## How we map literature → implementation

- Use Cowrie as an established honeypot baseline.
- Use AWS’s recommended trigger mechanism (S3 events → Lambda) for log processing.
- Use unsupervised clustering (DBSCAN baseline) and iterate features to better represent attacker behavior.

