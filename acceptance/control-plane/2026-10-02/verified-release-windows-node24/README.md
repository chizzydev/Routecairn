# Verified local fleet deployment

54 native/service/regression tests and eight actual Kubernetes acceptance groups passed. Namespace and service-process cleanup are confirmed. The native source snapshot and installed image runtime hashes were compared with current files before retaining this evidence.

Three fleet replicas, two independently enrolled TLS-connected worker pods, scale-out to four, pod replacement and persistent dashboard recovery were exercised on a single-node K3s cluster. KMS was exercised with Moto through the AWS SDK; managed AWS KMS and HSM operation are not asserted. The administrative dashboard remains a persistent SQLite singleton.

History retains the storage-reserve failure and the worker-refusal failure before bounded retry handling was fixed. Successful final proof is in native/ and kubernetes/. Private setup manifests and generated keys are not retained here.
