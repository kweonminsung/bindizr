{{- define "bindizr-stack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "bindizr-stack.fullname" -}}
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

{{- define "bindizr-stack.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "bindizr-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "bindizr-stack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bindizr-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "bindizr-stack.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "bindizr-stack.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "bindizr-stack.tsigSecretName" -}}
{{- default (printf "%s-tsig" (include "bindizr-stack.fullname" .)) .Values.tsig.existingSecret -}}
{{- end -}}

{{- define "bindizr-stack.databaseSecretName" -}}
{{- default (printf "%s-db" (include "bindizr-stack.fullname" .)) .Values.bindizr.database.existingSecret -}}
{{- end -}}

{{- define "bindizr-stack.mysql.fullname" -}}
{{- printf "%s-mysql" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "bindizr-stack.postgresql.fullname" -}}
{{- printf "%s-postgresql" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "bindizr-stack.databaseUrl" -}}
{{- if .Values.bindizr.database.serverUrl -}}
{{- .Values.bindizr.database.serverUrl -}}
{{- else if eq .Values.bindizr.database.type "mysql" -}}
{{- if .Values.mysql.enabled -}}
{{- printf "mysql://%s:%s@%s:3306/%s" .Values.mysql.auth.username .Values.mysql.auth.password (include "bindizr-stack.mysql.fullname" .) .Values.mysql.auth.database -}}
{{- else -}}
{{- required "Set bindizr.database.serverUrl, bindizr.database.existingSecret, or enable mysql.enabled when bindizr.database.type is mysql" .Values.bindizr.database.serverUrl -}}
{{- end -}}
{{- else if eq .Values.bindizr.database.type "postgresql" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "postgresql://%s:%s@%s:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "bindizr-stack.postgresql.fullname" .) .Values.postgresql.auth.database -}}
{{- else -}}
{{- required "Set bindizr.database.serverUrl, bindizr.database.existingSecret, or enable postgresql.enabled when bindizr.database.type is postgresql" .Values.bindizr.database.serverUrl -}}
{{- end -}}
{{- else -}}
{{- required "bindizr.database.type must be mysql or postgresql" "" -}}
{{- end -}}
{{- end -}}
