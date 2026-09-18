{{- /* Return the chart name with any configured override. */ -}}
{{- define "bindizr-chart.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /* Build the release-qualified resource name. */ -}}
{{- define "bindizr-chart.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- /* Render the common chart and release labels. */ -}}
{{- define "bindizr-chart.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "bindizr-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- /* Render the stable labels used by resource selectors. */ -}}
{{- define "bindizr-chart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bindizr-chart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- /* Choose the service account name for the release. */ -}}
{{- define "bindizr-chart.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "bindizr-chart.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- /* NOTIFY must reach every replica individually, so enumerate stable
per-pod headless names instead of the load-balanced service. */ -}}
{{- define "bindizr-chart.secondaryAddrs" -}}
{{- $fullname := include "bindizr-chart.fullname" . -}}
{{- $headless := printf "%s-bind9-headless" $fullname -}}
{{- range $i, $_ := until (.Values.bind9.replicas | int) -}}
{{- if $i }},{{ end -}}
{{- printf "%s-bind9-%d.%s:53" $fullname $i $headless -}}
{{- end -}}
{{- end -}}

{{- /* Choose the secret containing the database connection URL. */ -}}
{{- define "bindizr-chart.databaseSecretName" -}}
{{- default (printf "%s-db" (include "bindizr-chart.fullname" .)) .Values.bindizr.database.existingSecret -}}
{{- end -}}

{{- /* Non-empty while the chart hands bindizr an initial API token; with
       authentication off the token would do nothing. */ -}}
{{- define "bindizr-chart.initialTokenEnabled" -}}
{{- with .Values.bindizr.api.authentication -}}
{{- if and .required .initialToken.enabled -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{- /* Choose the secret containing the initial API token. */ -}}
{{- define "bindizr-chart.initialTokenSecretName" -}}
{{- default (printf "%s-initial-token" (include "bindizr-chart.fullname" .)) .Values.bindizr.api.authentication.initialToken.existingSecret -}}
{{- end -}}

{{- /* The initial API token: the value, else the one already created, else a
       fresh one. A render with no cluster behind it has nothing to look up, so
       it generates a different token each time. */ -}}
{{- define "bindizr-chart.initialToken" -}}
{{- $token := .Values.bindizr.api.authentication.initialToken.value -}}
{{- if not $token -}}
{{- $name := include "bindizr-chart.initialTokenSecretName" . -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- $key := .Values.bindizr.api.authentication.initialToken.secretKey -}}
{{- if and $existing (index $existing.data $key) -}}
{{- $token = index $existing.data $key | b64dec -}}
{{- else -}}
{{- $token = randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
{{- $token -}}
{{- end -}}

{{- /* Build the name of the bundled MySQL resources. */ -}}
{{- define "bindizr-chart.mysql.fullname" -}}
{{- printf "%s-mysql" (include "bindizr-chart.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /* Build the name of the bundled PostgreSQL resources. */ -}}
{{- define "bindizr-chart.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "bindizr-chart.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- /* Percent-encode one component of an assembled database URL; urlquery's + for a space would stay a literal + in userinfo. */ -}}
{{- define "bindizr-chart.urlComponent" -}}
{{- . | urlquery | replace "+" "%20" -}}
{{- end -}}

{{- /* Build the database connection URL from explicit or bundled-server settings. */ -}}
{{- define "bindizr-chart.databaseUrl" -}}
{{- if .Values.bindizr.database.url -}}
{{- .Values.bindizr.database.url -}}
{{- else if eq .Values.bindizr.database.type "mysql" -}}
{{- if .Values.mysql.enabled -}}
{{- printf "mysql://%s:%s@%s:%v/%s" (include "bindizr-chart.urlComponent" .Values.mysql.auth.username) (include "bindizr-chart.urlComponent" .Values.mysql.auth.password) (include "bindizr-chart.mysql.fullname" .) .Values.mysql.service.port (include "bindizr-chart.urlComponent" .Values.mysql.auth.database) -}}
{{- else -}}
{{- required "Set bindizr.database.url, bindizr.database.existingSecret, or enable mysql.enabled when bindizr.database.type is mysql" .Values.bindizr.database.url -}}
{{- end -}}
{{- else if eq .Values.bindizr.database.type "postgresql" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "postgresql://%s:%s@%s:%v/%s" (include "bindizr-chart.urlComponent" .Values.postgresql.auth.username) (include "bindizr-chart.urlComponent" .Values.postgresql.auth.password) (include "bindizr-chart.postgresql.fullname" .) .Values.postgresql.service.port (include "bindizr-chart.urlComponent" .Values.postgresql.auth.database) -}}
{{- else -}}
{{- required "Set bindizr.database.url, bindizr.database.existingSecret, or enable postgresql.enabled when bindizr.database.type is postgresql" .Values.bindizr.database.url -}}
{{- end -}}
{{- else -}}
{{- required "bindizr.database.type must be mysql or postgresql" "" -}}
{{- end -}}
{{- end -}}
