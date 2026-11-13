# STA — Supervised Temporary Access

Acesso privilegiado temporário e auditado para OpenShift, instalado como um operator (OLM).

> **Ferramenta não oficial.** O STA não é produto da Red Hat e **não tem suporte da Red Hat**.
> Use por sua conta e risco, e teste em um cluster não produtivo antes de usar em produção.

## O que o STA faz

- Qualquer usuário logado pode **solicitar** acesso privilegiado temporário:
  - `cluster-admin`, `cluster-status`, `cluster-reader` (acesso ao cluster);
  - `view`, `edit`, `admin` (acesso a um projeto escolhido).
- Quem **aprova** precisa ser cluster-admin e **não pode** estar no grupo de admins temporários.
- Prazo mínimo de 5 minutos e máximo de 24 horas. A expiração é automática, e a revogação é imediata.
- Cada concessão tem ticket (obrigatório), motivo e histórico.
- O painel mostra solicitações e concessões em tempo real, sem recarregar a página.
- A aba **Auditoria de usuários** lista os comandos executados pelos usuários com concessões. Ela consulta o LokiStack (OpenShift Logging) e só faz a consulta depois de clicar em **Pesquisar**.
- Um atalho **Painel STA** aparece no menu de aplicações do console (seção "STA (não oficial)").

Usuários no grupo `breakglass-temp-cluster-admins` não conseguem aprovar, não conseguem conceder `cluster-admin` a outros e não conseguem alterar os objetos do próprio STA. Ver "Limitações".

## Como funciona

- O **operator** (`operator/`) roda em `openshift-operators` e:
  - cria o namespace `breakglass-system`;
  - cria o CR `BreakglassPanel` padrão (`sta`) e instala o painel: Deployment, Service, Route, PVC de auditoria, RBAC e políticas de validação (ValidatingAdmissionPolicy);
  - descobre sozinho o gateway do LokiStack em `openshift-logging/logging-loki-gateway-http`, sem configuração manual;
  - cria o atalho do console (`ConsoleLink`);
  - aplica e mantém as concessões: cria o binding, mantém o grupo temporário e expira o acesso.
- O **painel** (`panel/`) é uma aplicação Flask atrás do oauth-proxy. Ele só lê e grava os objetos do STA com as credenciais do próprio usuário autenticado.
- As **concessões** são objetos `BreakglassGrant` no namespace `breakglass-system`. Os bindings são marcados com a label `breakglass.acme.io/grant=true` e anotações de solicitante, aprovador, ticket, motivo, prazo e expiração.
- O **bundle OLM** (`bundle/`) tem a CSV, os CRDs, o ícone e os metadados.

Não há formulário manual de criação no OperatorHub: o painel é a interface.

## Estrutura

```
operator/   controlador (kopf), Dockerfile e manifestos do painel e das políticas
panel/      aplicação do painel (Flask), Dockerfile
bundle/     bundle OLM: CSV, CRDs, ícone e metadados
install/    CatalogSource e Subscription (gerado pelo build.sh)
build.sh    constrói e publica as imagens e o índice do catálogo
scripts/    uninstall-manual.sh (remove uma instalação antiga ou manual)
docs/       documentação de apoio (Loki e OpenShift Logging)
```

## Requisitos

- Cluster OpenShift 4.x com acesso de cluster-admin.
- Docker ou Podman para o build, com login em um registry de contêineres (o exemplo usa `quay.io`).
- `oc` autenticado no cluster.
- Opcional, para a aba de auditoria: OpenShift Logging com LokiStack. Ver [docs/loki-setup.md](docs/loki-setup.md).

## Build e publicação

1. Ajuste o registry no topo do `build.sh` (variável `QUAY`) e a imagem do painel, se for mudar o nome.
2. Rode:

```
chmod +x build.sh
./build.sh
```

O script constrói e publica as imagens do operator (`sta-operator`), do painel (`sta-panel`) e do bundle (`sta-bundle`), gera o índice do catálogo com uma tag única por build (`sta-index:v0.1.0-<data>`) e atualiza `install/operator-install.yaml` com essa tag.

Se o registry for privado, o cluster precisa de um segredo de pull com acesso a ele.

## Instalação

```
oc apply -f install/operator-install.yaml
```

Isso cria o CatalogSource `sta-catalog` no `openshift-marketplace` e a Subscription `sta-operator` em `openshift-operators` (canal `alpha`, instalação automática). Depois de alguns minutos:

```
oc get csv -n openshift-operators | grep sta
oc get breakglasspanel -n breakglass-system
oc get pods,route -n breakglass-system
```

O painel aparece na Route `breakglass-panel`. Entre com um usuário do cluster.

### Reinstalar uma versão nova

```
oc delete subscription.operators.coreos.com sta-operator -n openshift-operators --ignore-not-found
oc delete csv sta-operator.v0.1.0 -n openshift-operators --ignore-not-found
oc apply -f install/operator-install.yaml
```

O catálogo precisa apontar para a tag nova. Use sempre o `install/operator-install.yaml` gerado pelo último `./build.sh`.

### Desinstalação

Remover a Subscription e a CSV desinstala o operator, mas não apaga:
- os CRDs `BreakglassGrant` e `BreakglassPanel`;
- as concessões existentes e seus bindings;
- o namespace `breakglass-system`;
- o atalho `breakglass-sta` do console.

Para remover tudo, use `scripts/uninstall-manual.sh` (ele pede confirmação), depois apague o atalho com `oc delete consolelink breakglass-sta`.

## Uso

1. **Solicitar:** no painel, escolha o papel, o projeto (se for o caso), o prazo, o ticket e o motivo.
2. **Aprovar:** um cluster-admin fora do grupo temporário aprova na aba de aprovação.
3. **Acompanhar:** a concessão fica `Active` e o binding é criado. Ao expirar, o binding é removido automaticamente.
4. **Revogar:** pelo painel, a qualquer momento. O binding é removido na hora.
5. **Auditar:** na aba de auditoria, escolha o período e o usuário e clique em **Pesquisar**.

## Limitações conhecidas

- **Não testado de ponta a ponta.** Build, instalação, painel no ar, Route, PVC e atalho do console foram verificados em um cluster de teste. O fluxo completo de solicitação, aprovação, expiração e revogação ainda não foi testado e precisa ser validado antes de uso real.
- **Permissões amplas do operator.** Para instalar o painel, o operator precisa criar RBAC, políticas, Routes e Deployments, e usar `escalate` e `bind` em roles. Na prática ele fica quase com privilégio de cluster-admin. Revise a CSV (`bundle/manifests/sta-operator.clusterserviceversion.yaml`) antes de instalar.
- **Leitura não pode ser escondida.** Um cluster-admin consegue ver o que quem tem acesso temporário faz no cluster, inclusive ler os objetos do STA. Os bloqueios impedem alteração, não leitura.
- **Dependência do LokiStack** para a aba de auditoria. Sem ele, a aba mostra que a fonte não está instalada.
- **Políticas de validação** dependem da versão do cluster (ValidatingAdmissionPolicy).

## Segurança

- O cookie do painel é gerado uma vez e guardado no segredo `breakglass-panel-cookie`. Trocá-lo derruba as sessões.
- Não há senhas nem tokens no repositório.

## Licença

A definir.
