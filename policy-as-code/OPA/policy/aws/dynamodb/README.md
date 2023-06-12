Following DYNAMODB Controls are implemented:

1. aws-dynamodb-m-1: Ensures server side encryption using AWS customer managed key (CMK)
2. aws-dynamodb-m-2: Ensures that vpc endpoint with a well written policy exists before creating resources
3. aws-dynamodb-m-3: Ensures enablement of both encryption in transit and at rest when creating your DAX cluster.