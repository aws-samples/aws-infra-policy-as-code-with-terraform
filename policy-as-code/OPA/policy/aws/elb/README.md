Following ELB Controls are implemented:

1. aws-elb-m-1: Ensure ELB access logs are enabled to log all calls made from ELB to backend
2. aws-elb-m-2: Ensure ELB target group connection termination is set to false
3. aws-elb-m-3: Ensure ELB should be reachable only to internal network
4. aws-elb-m-4: Ensure connections to LB and from LB to instances are encrypted
