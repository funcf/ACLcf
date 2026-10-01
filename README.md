# ACLcf
IP ACL route service app for Cloud Foundry

### How to use

> **Security Note:** This application is designed to be **fail-safe**. It will intentionally crash on startup if its required security perimeters are not defined. 
> You must push the app in a stopped state and inject the environment variables *before* starting it.

```bash
# clone the repository
git clone [https://github.com/funcf/ACLcf.git](https://github.com/funcf/ACLcf.git) && cd ACLcf

# push the app without starting it to allow setting environment variables first
cf push acl --no-start

# 1. Define the trusted routing infrastructure (Load Balancers, CF Routers)
# This is required to prevent IP spoofing by correctly identifying the true client
cf set-env acl TRUSTED_IPS "192.168.0.0/16,10.0.0.0/8"

# 2. Define the platform-managed allowed IPs (single IPs or CIDR blocks)
cf set-env acl ALLOWED_IPS "1.1.1.1,8.8.0.0/16"

# 3. Define customer-managed allowed IPs 
# Both ALLOWED_IPS and CONFIG_IPS are seamlessly merged at startup
cf set-env acl CONFIG_IPS "2.2.2.2"

# start the app now that the security perimeters are securely defined
cf start acl

# create a route service with this app where "example.com" is the shared public CF domain
cf create-user-provided-service acl-checker -r [https://acl.example.com](https://acl.example.com)

# bind the new route service to any of your other apps you want to protect
cf bind-route-service example.com --hostname my-other-app-to-be-protected acl-checker
```

### Guide 
See https://docs.cloudfoundry.org/services/route-services.html#user-provided for a more detailed explanation.
