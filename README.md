# KubeCon-EMEA-Tigera-2022

Since the demos are fairly short, it makes sense that we flush the data in the UI a little quicker:
``` 
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
```

If your cluster does not have applications, introduce one:
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Create the Product Tier:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/product.yaml
```  

## Zone-Based Architecture  
Create the DMZ Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/dmz.yaml
```
Create the Trusted Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/trusted.yaml
``` 
Create the Restricted Policy:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/restricted.yaml
```
Create the Default-Deny Policy:
```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/KubeCon-EMEA-Tigera-2022/main/default-deny.yaml
```

- This ```default-deny``` policy is in a ```staged``` mode and also in the wrong ```tier``` <br/>
- Show how easy it is to drag policies between different tiers. Move the ```default-deny``` policy to the ```product``` tier <br/>
- To break communication between pods, upgrade the ```default-deny``` policy from ```staged``` to ```enforced```

## Next Steps

- Use Service Graph to show broken connection between ```frontend``` and ```backend``` pods to the ```logging``` pod <br/>
- Use Policy Recommendation to resolve this issue of unwanted denied traffic

#### Confirm all policies are running:
```
kubectl get networkpolicies.p -n storefront -l projectcalico.org/tier=product
```

## Allow Kube-DNS Traffic: 

Determine a DNS provider of your cluster (mine is 'coredns' by default)
```
kubectl get deployments -l k8s-app=kube-dns -n kube-system --show-labels | grep k8s-app=kube-dns
```    
Allow traffic for Kube-DNS / CoreDNS:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/allow-kubedns.yaml
```

## Introduce the Rogue Application:
This application will perform TCP Port Scanning on pods in different namespaces
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml -n storefront
``` 

- Go back to the service graph to confirm the unusual flows created by the attacker app (search <5 mins in the filter view) <br/>
- This is fine as a manual process, but it makes sense for us to alert on specific unusual behaviours in our flows:

Alert on ```lateral access``` to a specific namespace:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/alerting/lateral-access.yaml
``` 

Introduce a test application that already has the label of ```security=strict```:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/test.yaml
```

While we are at it, we should secure those new workloads via security policies:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/test-app.yaml
```
- The goal here is to be notified when there is unusual behaviour ahead of time. <br/>
- The user can investigate using automation scripting to label the source attacker pod with the key-pair values ```quarantine=true``` <br/>
- Alternatively, we can do this manually - as we will demonstrate later in the repository.

Create a ```quarantine policy``` in the ```tigera-security``` tier: 
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/quarantine.yaml
```
If you wish to quarantine the rogue pod, label the pod with context:
```
kubectl label pod <attacker-app> -n storefront quarantine=true
```
The idea here is that the traffic will get denied at the earlier possible stage

## Securing your hosts:

Automatically register your nodes as Host Endpoints (HEPS). To enable automatic host endpoints, edit the default KubeControllersConfiguration instance, and set ``` spec.controllers.node.hostEndpoint.autoCreate```  to ```true``` for those ```HostEndpoints``` :

```
kubectl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

Add the label ```kubernetes-host``` to all nodes and their host endpoints:
```
kubectl label nodes --all kubernetes-host=  
```
This tutorial assumes that you already have a tier called '```host-endpoints```' in Calico Cloud:  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/node-tier.yaml
```
Once the tier is created, Build a policies for your master and worker nodes: <br/>
<br/>

Master Node:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/master.yaml
```
Worker Node:
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/policies/worker.yaml
```

#### Label based on node purpose
To select a specific set of host endpoints (and their corresponding Kubernetes nodes), use a policy selector that selects a label unique to that set of host endpoints. <br/>
For example, if we want to add the label ```env=master``` to nodes named node1 and node2:

```
kubectl label node master1 env=master
kubectl label node worker1 env=worker
```
