#!/usr/bin/env bash
# Constrói e envia as imagens do STA para o Quay (quay.io/marcruz) e gera o índice do catálogo.
# Pré-requisitos: docker ou podman rodando, e login no Quay (o script pede).
# ATENÇÃO: não testado. Valide cada etapa antes de seguir.
set -euo pipefail
cd "$(dirname "$0")"

QUAY=quay.io/marcruz
VERSION=v0.1.0
PLATFORM=linux/amd64   # o cluster é x86_64; o Mac pode ser arm64
TMP=$(mktemp -d)

if command -v podman >/dev/null 2>&1; then CT=podman
elif command -v docker >/dev/null 2>&1; then CT=docker
else echo "Instale podman ou docker."; exit 1
fi
# opm roda dentro do container oficial, então não precisa instalar nada além do docker/podman
# Roda o opm na arquitetura nativa do Mac; emulação quebra o binário Go
case "$(uname -m)" in
  arm64|aarch64) HOST_PLATFORM=linux/arm64 ;;
  *)             HOST_PLATFORM=linux/amd64 ;;
esac
OPM="$CT run --rm --platform $HOST_PLATFORM --entrypoint /bin/opm -v $PWD/bundle:/bundle quay.io/operator-framework/opm:v1.46.0"

$CT login quay.io

# 1. Imagem do operator (controlador)
$CT build --platform "$PLATFORM" -t "$QUAY/sta-operator:$VERSION" operator
$CT push "$QUAY/sta-operator:$VERSION"

# 1b. Imagem do painel (interface + auditoria), instalada pelo operator
$CT build --platform "$PLATFORM" -t "$QUAY/sta-panel:$VERSION" panel
$CT push "$QUAY/sta-panel:$VERSION"

# 2. Imagem do bundle (manifests + metadata)
cp bundle/bundle.Dockerfile "$TMP/Dockerfile"
cp -R bundle/manifests bundle/metadata "$TMP/"
$CT build --platform "$PLATFORM" -t "$QUAY/sta-bundle:$VERSION" "$TMP"
$CT push "$QUAY/sta-bundle:$VERSION"

# 3. Catálogo em formato FBC, gerado a partir do bundle local
mkdir -p "$TMP/catalog"
# FBC em JSON (objetos concatenados, sem separadores): é o formato que o opm serve lê
$OPM init sta-operator --default-channel=alpha > "$TMP/catalog/index.json"
$OPM render /bundle -o json >> "$TMP/catalog/index.json"
printf '{"schema":"olm.channel","package":"sta-operator","name":"alpha","entries":[{"name":"sta-operator.%s"}]}\n' "$VERSION" >> "$TMP/catalog/index.json"

cat > "$TMP/Dockerfile" <<'EOF'
FROM quay.io/operator-framework/opm:v1.46.0
ADD catalog /configs
LABEL operators.operatorframework.io.index.configs.v1=/configs
ENTRYPOINT ["/bin/opm"]
CMD ["serve", "/configs"]
EXPOSE 50051
EOF

# Tag única por build: o OLM não rebaixa a tag "latest" em cache, então o cluster não via o índice novo
IDX_TAG="$VERSION-$(date +%Y%m%d%H%M%S)"
$CT build --platform "$PLATFORM" -t "$QUAY/sta-index:$IDX_TAG" "$TMP"
$CT push "$QUAY/sta-index:$IDX_TAG"
# Aponta o CatalogSource para a tag nova
sed -i.bak "s|sta-index:[^ ]*|sta-index:$IDX_TAG|" install/operator-install.yaml && rm -f install/operator-install.yaml.bak
echo "Índice publicado: $QUAY/sta-index:$IDX_TAG (install/operator-install.yaml atualizado)"

echo "Imagens publicadas em $QUAY. Próximo passo: oc apply -f install/operator-install.yaml"
echo "Se os repositórios forem privados, crie o segredo de pull (ver instruções)."
