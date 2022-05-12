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

## Dynamic Packet Capture:

Check that there are no packet captures in this directory  
```
ls *pcap
```
A Packet Capture resource (```PacketCapture```) represents captured live traffic for debugging microservices and application interaction inside a Kubernetes cluster.</br>
https://docs.tigera.io/reference/calicoctl/captured-packets  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
Confirm this is now running:  
```  
kubectl get packetcapture -n storefront
```
Once the capture is created, you can delete the collector:
```
kubectl delete -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
#### Install a Calicoctl plugin  
Use the following command to download the calicoctl binary:</br>
https://docs.tigera.io/maintenance/clis/calicoctl/install#install-calicoctl-as-a-kubectl-plugin-on-a-single-host
``` 
curl -o kubectl-calico -O -L  https://docs.tigera.io/download/binaries/v3.7.0/calicoctl
``` 
Set the file to be executable.
``` 
chmod +x kubectl-calico
```
Verify the plugin works:
``` 
./kubectl-calico -h
``` 
#### Move the packet capture
```
./kubectl-calico captured-packets copy storefront-capture -n storefront
``` 
Check that the packet captures are now created:
```
ls *pcap
```
#### Install TSHARK and troubleshoot per pod 
Use Yum To Search For The Package That Installs Tshark:</br>
https://www.question-defense.com/2010/03/07/install-tshark-on-centos-linux-using-the-yum-package-manager
```  
sudo yum install wireshark
```  
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice1
``` 
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice2
```  

#### Additional was of configuring packet capture jobs:

In the following example, we select all workload endpoints in ```storefront```  namespace.
```  
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: sample-capture-all
  namespace: storefront
spec:
  selector: all()
```  

In the following example, we select all workload endpoints in ```storefront``` namespace and ```Only TCP``` traffic.

```
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: storefront-capture-all-tcp
  namespace: storefront
spec:
  selector: all()
  filters:
    - protocol: TCP
```

You can schedule a PacketCapture to start and/or stop at a certain time. <br/>
Start and end time are defined using ```RFC3339 format```.
```
apiVersion: projectcalico.org/v3
kind: PacketCapture
metadata:
  name: sample-capture-all-morning
  namespace: storefront
spec:
  selector: all()
  startTime: "2021-12-02T11:05:00Z"
  endTime: "2021-12-02T11:25:00Z"
```
In the above example, we schedule traffic capture for 15 minutes between 11:05 GMT and 11:25 GMT for all workload endpoints in ```storefront``` namespace.

## Calico Deep Packet Inspection
Configuring DPI using Calico Enterprise <br/>
Security teams need to run DPI quickly in response to unusual network traffic in clusters so they can identify potential threats. 

### Introduce a test application:
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Also, it is critical to run DPI on select workloads (not all) to efficiently make use of cluster resources and minimize the impact of false positives.

### Bring in a Rogue Application
```
kubectl apply -f https://installer.calicocloud.io/rogue-demo.yaml
```

Calico Enterprise provides an easy way to perform DPI using Snort community rules.

### Create DeepPacketInspection resource: 
In this example we will enable DPI on backend pod in storefront namespace:

```
apiVersion: projectcalico.org/v3
kind: DeepPacketInspection
metadata:
  name: database
  namespace: storefront
spec:
  selector: app == "backend"
```

You can disable DPI at any time, selectively configure for namespaces and endpoints, and alerts are generated in the Alerts dashboard in Manager UI. 

### Check that the "tigera-dpi" pods created successfully
It's a deaemonSet so one pod should created in each node:

```
kubectl get pods -n tigera-dpi
```

### Make sure that all pods are in running state
Trigger Snort rule from attacker pod to backend.storefront

```
kubectl exec -it $(kubectl get po -l app=attacker-app -ojsonpath='{.items[0].metadata.name}') -- sh -c "curl http://backend.storefront.svc.cluster.local:80 -H 'User-Agent: Mozilla/4.0' -XPOST --data-raw 'smk=1234'"
```

### Now, go and check the Alerts page in the UI
You should see a signature triggered alert. <br/>
Once satisfied with the alerts, you can disable Deep Packet Inspection via the below command:
```
kubectl delete DeepPacketInspection database -n storefront 
```

### Hipstershop Reference
```
apiVersion: projectcalico.org/v3
kind: DeepPacketInspection
metadata:
  name: hipstershop-dpi-dmz
  namespace: hipstershop
spec:
  selector: zone == "dmz"
```

### Malware Detection
Detect the presence of malware running in cloud-native applications and get alerts when malicious programs are running in your cluster.

#### Enable on Nodes
Malware detection is disabled by default. <br/>
The DaemonSet has a nodeSelector constraint ```enable-tigera-runtime-security: t```, which means that it will not initially run on any nodes, because there are no nodes with an enable-tigera-runtime-security: t label.

```
kubectl get ds runtime-reporter -n calico-system -o yaml | sed '/enable-tigera-runtime-security/d' | kubectl apply -f -
```

#### Enable on specific nodes
To enable malware detection on a particular node, add the ```enable-tigera-runtime-security: t``` label to that node. For example:

```
kubectl label nodes <node-name> enable-tigera-runtime-security=t
```


![malware](https://user-images.githubusercontent.com/82048393/166684959-a385610f-2a7e-45f1-bd1f-56d514d86686.png)
