# ACLcf
IP whitelisting route service app for Cloud Foundry

### How to use

```bash
# create app as a precondition to set the whitelist
cf create-app acl

# edit IP whitelist, can contain single IPs or whole subnet ranges, separated by comma
cf set-env acl WHITELIST_IPS "1.1.1.1,8.8.0.0/16"

# push this app
git clone https://github.com/funcf/ACLcf.git && cd ACLcf
cf push acl

# create a route service with this app where "example.com" is the shared public CF domain
cf create-user-provided-service acl-checker -r https://acl.example.com

# bind the new route service to any of your other apps you want to protect
cf bind-route-service example.com --hostname my-other-app-to-be-protected acl-checker
```

### Guide 
See https://docs.cloudfoundry.org/services/route-services.html#user-provided for a more detailed explanation.
