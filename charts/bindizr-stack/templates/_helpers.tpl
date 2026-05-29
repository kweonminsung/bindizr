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
