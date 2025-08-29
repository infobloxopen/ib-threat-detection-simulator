## Data Submission

### Description:
This script will GET real threat's state active data (/tide/api/data/threats/state) from source_env such as prod, 
build a payload and POST to destination_env such as env-2a/stage (POST to profile: ANALYST, or IID_IRD). 
Data is query from profile "IID:ANALYST,IID:IID_IRD" with these fields: `"type,host,class,property,threat_level,confidence,detected,threat_score,threat_score_rating,threat_score_vector,confidence_score,confidence_score_rating,confidence_score_vector,risk_score,risk_score_rating,risk_score_vector,target,extended"` to reduce the response size and speed up request. If you'd like more field then add more in this list, if you'd like entire record then comment out the `fields` in `params` from the code.


```
   params = {
    "fields" : "type,host,class,property,threat_level,confidence,detected,threat_score,threat_score_rating,threat_score_vector,confidence_score,confidence_score_rating,confidence_score_vector,risk_score,risk_score_rating,risk_score_vector,target,extended",
    "profiles": "IID:ANALYST,IID:IID_IRD"
    }
```

### Requirement for environment vars: (Please refer to commands in ** Retrieve service_key ** on how to get service_token)
- Source env csp token: `export SOURCE_KEY="Token service_token"`
- Destination env csp token: `expofrt DEST_KEY="Token service_token"`

### Require arguments to run this script:  
  
    `-type` for threat type, 
    `-rlimit` for how many record to GET from source env, 
    `-prop` for what property to GET from soource env, 
    `-src` and `-dest` for source and destination environment (ex: env-2a.infoblox.com)
    `-lookalike` specify if you're working with lookalike data set so the script will filter record with `target` non empty to submit.
  

##### Example command to get 10000 lookalike records in prod and submit to env-2a:
  `python3 submit_data.py -type host -rlimit 10000 -src csp.infoblox.com -dest env-2a.test.infoblox.com -prop Suspicious_Lookalike -lookalike yes`
  `python3 submit_data.py -type host -rlimit 10000 -src csp.infoblox.com -dest env-2a.test.infoblox.com -prop Phishing_Lookalike,Suspicious_Lookalike -lookalike yes`

#### Example command to get 100 outliner records (Suspicious_EmergentDomain) in prod and submit to env-2a:
  `python3 submit_data.py -type host -rlimit 100 -src csp.infoblox.com -dest env-2a.test.infoblox.com -prop Suspicious_EmergentDomain`


### Retrieve service_key (csp token)
** Be mindful when using production's service key to submit data **
It's fine to use it to request data. 

In this script, we'll use prod's key to request (GET) data, and other evironment's key to submit (POST) data

For example, if you want to get data from prod, and submit to env-2a, then follow the instruction below for `prd-1` and `env-2a`.
Then export the csp token into the required environment variables specified in the python script.

#### In terminal:
- Teleport to the environment(s)
- Run this command to show encoded token string:
    `kubectl get secret tideng-iid-service-key -n tideng -oyaml`
- Copy the encoded string under `data.key`
    ```
    apiVersion: v1
    data:
    key: VG9...NmNA==
    kind: Secret
    metadata:
    creationTimestamp: "2022-02-28T12:35:54Z"
    labels:
        app.kubernetes.io/managed-by: spinnaker
        app.kubernetes.io/name: env-2a-integration
        infoblox.com/Lifecycle: EngQA
        infoblox.com/Name: tideng
    name: tideng-iid-service-key
    namespace: tideng
    ownerReferences:
    - apiVersion: spacecontroller.infoblox-cto.github.com/v1alpha1
        blockOwnerDeletion: true
        controller: true
        kind: Space
        name: tideng-iid-service-key
        uid: some_uid
    resourceVersion: "1363271"
    uid: another_uid
    type: Opaque
    ```
- Encode the string: 
    `echo 'VG9rZ.....NA==' | base64 -D`
- Copy the decoded token, for example: `Token e8d....` 
- Set environemnt variable: `export $REQUIRED_ENV="Token e8d..."`