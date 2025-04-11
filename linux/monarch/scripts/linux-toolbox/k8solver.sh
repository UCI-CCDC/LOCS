#!/usr/bin/env bash

WORK_DIR="./k8s-backup"
WORK_DIR_NAMED="${WORK_DIR}/$1"

mkdir -p "$WORK_DIR_NAMED"

RESOURCES=("deployments" "services" "secrets" "configmaps" "ingresses" "statefulsets" "daemonsets" "pvc")
backup_resource() {
    local RESOURCE_TYPE=$1
    local NAMESPACE=$2
    echo "Backing up ${RESOURCE_TYPE} for namespace ${NAMESPACE}..."
    resources=$(kubectl get ${RESOURCE_TYPE} -n ${NAMESPACE} -o custom-columns=":metadata.name")
    for resource in $resources; do
        kubectl get ${RESOURCE_TYPE} -n ${NAMESPACE} -o yaml > "${WORK_DIR_NAMED}/${NAMESPACE}/${resource}-${RESOURCE_TYPE}.yaml"
        echo "${resource}-${RESOURCE_TYPE} backed up successfully."
    done
    echo "${RESOURCE_TYPE} for namespace ${NAMESPACE} backed up successfully."
}

namespaces=$(kubectl get namespaces -o custom-columns=":metadata.name")

for namespace in $namespaces; do
    echo "Backing up namespace: ${namespace}..."
    mkdir -p "${WORK_DIR_NAMED}/${namespace}"

    for RESOURCE in "${RESOURCES[@]}"; do
        backup_resource "$RESOURCE" "$namespace"
    done
done


pvs=$(kubectl get pv -o custom-columns=":metadata.name")
for pv in pvs; do
    kubectl get pv -o yaml > "${WORK_DIR_NAMED}/$pv-pv.yaml"
done