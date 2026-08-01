# Running llm-guard on Kubernetes (local, free)

These manifests deploy `llm-guard` to a Kubernetes cluster with security
hardening applied. You can run everything locally at no cost using `kind`
(Kubernetes-in-Docker) or `minikube`.

## Prerequisites

- Docker (running)
- `kubectl`
- `kind` (or `minikube`)

## Steps (using kind)

```bash
# 1. Create a local cluster
kind create cluster --name llm-guard

# 2. Build the image and load it into the cluster
docker build -t llm-guard:latest ..
kind load docker-image llm-guard:latest --name llm-guard

# 3. Apply the manifests
kubectl apply -f configmap.yaml
kubectl apply -f secret.example.yaml      # replace with a real secret first
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f networkpolicy.yaml

# 4. Check it's running
kubectl get pods
kubectl get svc

# 5. Test it (forward the service port to your machine)
kubectl port-forward svc/llm-guard 8080:8080
# then in another terminal:
curl http://localhost:8080/health
```

Tear down with `kind delete cluster --name llm-guard`.

## The security hardening, explained

Each setting here is a real Kubernetes security best practice:

| Setting | What it does | Why it matters |
|---------|--------------|----------------|
| `runAsNonRoot` + `runAsUser: 10001` | Runs the container as an unprivileged user | If the app is compromised, the attacker isn't root |
| `readOnlyRootFilesystem: true` | The container's filesystem can't be written to | Stops an attacker writing malware or tampering |
| `allowPrivilegeEscalation: false` | The process can't gain more privileges | Blocks a common escalation path |
| `capabilities: drop [ALL]` | Removes all Linux kernel capabilities | Least privilege — the app needs none |
| `seccompProfile: RuntimeDefault` | Restricts which syscalls the container can make | Shrinks the kernel attack surface |
| `resources.limits` | Caps CPU and memory | One pod can't starve the node (DoS defense) |
| `Secret` (not ConfigMap) for sensitive values | Keeps secrets separate from plain config | Secrets get different handling and RBAC |
| `NetworkPolicy` | Restricts pod traffic to only what's needed | Limits lateral movement if compromised |
| `ClusterIP` service | Not exposed publicly by default | Smaller external attack surface |
| liveness/readiness probes | K8s restarts unhealthy pods, only routes to ready ones | Availability + resilience |

This is "secure by default" at the infrastructure layer — the same mindset as
the tool itself, applied to how it runs.
