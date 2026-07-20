#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deployment/docker-compose.yml"
DATASET_DIR="${ROOT_DIR}/dataset/output"

DRY_RUN=0
COMPOSE_UP=0

for arg in "$@"; do
  case "${arg}" in
    --dry-run)
      DRY_RUN=1
      ;;
    --compose-up)
      COMPOSE_UP=1
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

echo "ETIP root: ${ROOT_DIR}"
echo "Dataset dir: ${DATASET_DIR}"
mkdir -p "${DATASET_DIR}"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "Dry run complete. No Docker commands executed."
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for deployment automation" >&2
  exit 1
fi

docker network create etip-lab >/dev/null 2>&1 || true

if [[ "${COMPOSE_UP}" == "1" ]]; then
  docker compose -f "${COMPOSE_FILE}" up -d collector
else
  echo "Docker network prepared. Pass --compose-up to start collector service."
fi
