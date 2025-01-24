{{- define "chart.fullname" -}}
  {{- $name := .Chart.Name }}          
  {{- $namespace := .Release.Namespace }}   
  {{- printf "%s" $name | trunc 63 | trimSuffix "-" }}   
{{- end }}
