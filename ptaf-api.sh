#!/usr/bin/env bash

API_URL='https://af.ptcloud.ru/api/ptaf/v4'
HEADERS=( -H "Cookie: af_instance=https://new.af.ptcloud.ru" -H "Content-Type: application/json" )
AUTH_TOKEN=
ACCESS_TOKEN=

help() {
	\echo "Usage: $0 -u USERNAME -p 'PASSWORD' { FUNCTION [ ARGS ] }"
	\echo "Functions: show_app [ 'APPLICATION' ] | show_template [ 'TEMPLATE' ] |"
	\echo "           show_rule 'TEMPLATE' [ 'RULE' ] | show_action [ 'ACTION' ] |"
	\echo "           add_template 'TEMPLATE' | add_app 'APPLICATION' 'HOST1 HOST2' |"
	\echo "           add_host 'APPLICATION' 'HOST1 HOST2' | add_list 'NAME' FILE |"
	\echo "           replace_action 'TEMPLATE' 'OLD' 'NEW'"
}

main() {
	username=
	password=
	while \getopts "hu:p:" opt; do
		case "$opt" in
			h) help; \exit 0;;
			u) username="$OPTARG";;
			p) password="$OPTARG";;
			*) help; err;;
		esac
	done

	if [[ -z "$username" ]] || [[ -z "$password" ]]; then
		help; err "missing argument"
	fi

	generate_tokens "$username" "$password"
	\shift 2
	"${@:3}"
	delete_tokens
}

add_template() {
	template="$1"

	if [[ -z "$template" ]]; then
		err "missing argument"
	fi

	def_template_id=$( show_def_template | jq -r '.id' -- )
	res=$(
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user \
			-d '{"name": "'"$template"'", "templates": ["'$def_template_id'"], "has_user_rules": false}' --
	)
	user_template_id=$( jq -r '.id' -- <<< "$res" )

	if ! is_uuid "$user_template_id"; then
		err "$res"
	fi

	\echo "$template [ $user_template_id ] created"
	set_template "$user_template_id"
}

set_template() {
	template="$1"

	if [[ -z "$template" ]]; then
		err "missing argument"
	fi

	template_id=

	if is_uuid "$template"; then
		template_id="$template"
	else
		template_id=$( show_template "$template" | \jq -r '.id' -- )
	fi

	rules_to_be_disabled=(
		 "Successful authentication"
		 "Failed authentication"
		 "Request rate limit"
		 "X-Content-Type-Options"
		 "X-Frame-Options"
		 "X-XSS-Protection"
		 "Inject CSRF token into web page"
		 "Validate CSRF token"
		 "Same session ID used by multiple IP addresses"
	)

    \echo
	for rule in "${rules_to_be_disabled[@]}"; do
		rule_id=$( show_rule "$template_id" "$rule" | \jq -r '.id' -- )

		\curl -s -X PATCH \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user/"$template_id"/rules/"$rule_id" \
			-d '{"enabled": false}' \
			| \jq -r '. | "\(.name): \(.enabled)"' -- &
	done
	\wait

	rules_to_be_enabled=(
		"Authentication Bypass in Veeam Backup Enterprise Manager (CVE-2024-29849)"
		"Bitrix24 Insecure File Append RCE"
		"Bitrix24 RCE via PHAR deserialization"
		"Bitrix Landing RCE"
		"Check Point CVE-2024-24919 Path Traversal"
		"Confluence CVE-2023-22515 Broken Access Control"
		"Confluence RCE CVE-2023-22527"
		"PHP CGI Argument Injection Vulnerability (CVE-2024-4577)"
		"Spring Cloud Function RCE"
		"TeamCity CVE-2024-27198 Authentication Bypass"
		"Malicious PDF object in uploaded file"
		"IP address in Host header"
		"Mail Injection"
		"Block all types of GraphQL introspection"
	)

	\echo
	for rule in "${rules_to_be_enabled[@]}"; do
		rule_id=$( show_rule "$template_id" "$rule" | \jq -r '.id' -- )

		\curl -s -X PATCH \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user/"$template_id"/rules/"$rule_id" \
			-d '{"enabled": true}' \
			| \jq -r '. | "\(.name): \(.enabled)"' -- &
	done
	\wait

	block_action_id=$( show_action 'Block' | jq -c '.id' )
	log_action_id=$( show_action 'Log to db' | jq -c '.id' )
	declare -A rules_to_be_customized=(
		["Cookie security"]='{"enabled": false, "variables": {"security_attributes": {"samesite": {"enabled": true, "override": true, "mode": "Lax"}, "httponly": {"enabled": true}, "secure": {"enabled": true}}}}'
		["HTTP Strict-Transport-Security"]='{"enabled": false, "variables": {"includeSubDomains": false}}'
		["Referrer-Policy"]='{"enabled": false, "variables": {"mode": "strict_origin_when_cross_origin"}}'
		["Origin or referrer not allowed"]='{"variables": {"empty_referer_allowed": false}}'
		["Illegal HTTP version"]='{"variables": {"allowed_protocol_versions": ["HTTP/1.1", "HTTP/2", "HTTP/2.0"]}}'
		["HTTP limit has been exceeded"]='{"variables": {"proxy_urls_hard_limits": ["/*"], "request_proxy_urls_pooloverflow": ["/*"], "proxy_urls_max_request_len": ["/*"]}, "actions": ['"$block_action_id"','"$log_action_id"']}'
		["Sensitive Information Leakage"]='{"variables": {"checks": ["common", "sql", "java", "php", "iis", "apache", "nginx", "portal_login", "version_leakage", "private_keys"]}}'
		["Preprocess encoded HTTP parameters"]='{"variables": {"decode_params": {"REQUEST_URI": ["url_decode"], "REQUEST_POST": ["json", "xml", "gzip", "url_decode"], "REQUEST_HEADERS": ["json", "xml", "gzip", "url_decode"], "REQUEST_COOKIES": ["json", "xml", "gzip", "url_decode"], "REQUEST_FILES": ["json", "xml", "gzip", "url_decode"], "REQUEST_GET": ["json", "xml", "graphql", "gzip", "url_decode"], "REQUEST_BODY": ["json", "xml", "graphql", "gzip", "url_decode"], "REQUEST_PATH": ["url_decode"]}}}'
		["Vulnerability Scanner"]='{"actions": ['"$block_action_id"','"$log_action_id"']}'
		["PHP object injection"]='{"variables": {"check_vars": {"REQUEST_GET": ["keys", "values", "json", "xml", graphql], "REQUEST_POST": ["keys", "values", "json", "xml", "url_decode"], "REQUEST_COOKIES": ["keys", "values", "json", "xml"], "REQUEST_HEADERS": ["values", "json", "xml"], "REQUEST_PATH": ["values"], "REQUEST_BODY": ["json", "xml", "graphql"]}}}'
	)

	\echo
	for rule in "${!rules_to_be_customized[@]}"; do
		rule_id=$( show_rule "$template_id" "$rule" | \jq -r '.id' -- )

		\curl -s -X PATCH \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user/"$template_id"/rules/"$rule_id" \
			-d "${rules_to_be_customized[$rule]}" \
			| \jq -r '. | "\(.name): \(.variables)"' -- &
	done
	\wait
}

add_app() {
	app="$1"
	hosts=( "$2" )

	if [[ -z "$app" ]] || [[ ! "${hosts[@]}" ]]; then
		err "missing argument"
	fi

	template_id=$( show_template "$app" | \jq -r '.id' -- )

	if ! is_uuid "$template_id"; then
		template_id=$( show_def_template | \jq -r '.id' -- )
	fi

	upd_hosts=$( to_json $( to_arr "${hosts[@]}" ) )
	res=$(
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/applications \
			-d '{"name": "'"$app"'", "protection_mode": "ACTIVE_DETECTION", "hosts": ['"$upd_hosts"'], "locations": ["/"], "policy_template_id": "'"$template_id"'"}' --
	)
	app_id=$( jq -r '.id' -- <<< "$res" )

	if ! is_uuid "$app_id"; then
		err "$res"
	fi

	\echo "$app [ $app_id ] created"
}

add_host() {
	app="$1"
	hosts=( "$2" )

	if [[ -z "$app" ]] || [[ ! "${hosts[@]}" ]]; then
		err "missing argument"
	fi

	res=$( show_app "$app" )
	app_id=

	if is_uuid "$app"; then
		app_id="$app"
	else
		app_id=$( jq -r '.id' -- <<< "$res" )
	fi

	if [[ -z "$app_id" ]]; then
		err "$res"
	fi

	old_hosts=$( to_json $( to_arr $( \jq -r '.hosts[]' -- <<< "$res" ) ) )
	new_hosts=$( to_json $( to_arr "${hosts[@]}" ) )

	if [[ -n "$old_hosts" ]]; then
		upd_hosts="$new_hosts,$old_hosts"
	else
		upd_hosts="$new_hosts"
	fi

	\curl -s -X PATCH \
		"${HEADERS[@]}" \
		"$API_URL"/config/applications/"$app_id" \
		-d '{"hosts": ['"$upd_hosts"']}' \
		| \jq -r '. | "\(.name): \(.hosts)"' --
}

replace_action() {
	template="$1"
	old_action="$2"
	new_action="$3"

	if [[ -z "$template" ]] || [[ -z "$old_action" ]] || [[ -z "$new_action" ]]; then
		err "missing argument"
	fi

	old_action_id=
	new_action_id=
	res=$( show_action )
	
	if is_uuid "$old_action"; then
		old_action_id="$old_action"
	else
		old_action_id=$( \jq -r '.items[] | select(.name == "'"$old_action"'").id' -- <<< "$res" )
	fi

	if is_uuid "$new_action"; then
		new_action_id="\"$new_action\""
	else
		new_action_id=$( \jq -c '.items[] | select(.name == "'"$new_action"'").id' -- <<< "$res" )
	fi

	if [[ -z "$old_action_id" ]] || [[ -z "$new_action_id" ]]; then
		err "$res"
	fi

	template_id=$( show_template "$template" | \jq -r '.id' -- )
	rule_ids=( $( to_arr $( show_rule "$template_id" | \jq -r '.items[] | .id' -- ) ) )
	\declare -A rules_to_be_customized

	echo "Replacing $old_action [ \"$old_action_id\" ] with $new_action [ $new_action_id ]"
	for rule_id in "${rule_ids[@]}"; do
		rule_actions=( $( to_arr $( show_rule "$template_id" "$rule_id" | \jq -r '.actions[]' 2> /dev/null -- ) ) )
		if [[ "${rule_actions[@]}" =~ "$old_action_id" ]]; then
			rule_actions_wo_old=$( to_json $( to_arr "${rule_actions[@]/$old_action_id}" ) )
			if [[ -n "$rule_actions_wo_old" ]]; then
				rules_to_be_customized["$rule_id"]="$new_action_id,$rule_actions_wo_old"
			else
				rules_to_be_customized["$rule_id"]="$new_action_id"
			fi
		fi
	done

	if [[ ! "${rules_to_be_customized[@]}" ]]; then
		exit 0
	fi

	for rule_id in "${!rules_to_be_customized[@]}"; do
		\curl -s -X PATCH \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user/"$template_id"/rules/"$rule_id" \
			-d '{"actions": ['"${rules_to_be_customized[$rule_id]}"']}' \
			| \jq -r '. | "\(.name): \(.actions)"' --
	done
}

add_list() {
	name="$1"
	file="$2"

	if [[ -z "$name" ]] || [[ -z "$file" ]]; then
		err "missing argument"
	fi

	\curl -s \
		"${HEADERS[@]/application\/json/multipart\/form-data}" \
		-F name="$name" -F type=STATIC -F file=@"$file" \
		"$API_URL"/config/global_lists
}

show_app() {
	app="$1"

	if [[ "$app" ]]; then
		if is_uuid "$app"; then
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/applications/"$app" --
		else
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/applications | \jq -c '.items[] | select(.name == "'"$app"'")' --
		fi
	else
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/applications --
	fi
}

show_template() {
	template="$1"

	if [[ "$template" ]]; then
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user \
			| \jq -c '.items[] | select(.name == "'"$template"'")' --
	else
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user --
	fi
}

show_def_template() {
	\curl -s \
		"${HEADERS[@]}" \
		"$API_URL"/config/policies/templates/vendor \
		| \jq -c '.items[] | select(.name == "Default Template")' --
}

show_rule() {
	template="$1"
	rule="$2"
	template_id=

	if [[ -z "$template" ]]; then
		err "missing argument"
	else
		if is_uuid "$template"; then
			template_id="$template"
		else
			template_id=$( show_template "$template" | jq -r '.id' )
		fi
	fi

	if [[ "$rule" ]]; then
		if is_uuid "$rule"; then
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/policies/templates/user/"$template_id"/rules/"$rule" --
		else
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/policies/templates/user/"$template_id"/rules \
				| \jq -c '.items[] | select(.name == "'"$rule"'")' --
		fi
	else
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/policies/templates/user/"$template_id"/rules --
	fi
}

show_action() {
	action="$1"

	if [[ "$action" ]]; then
		if is_uuid "$action"; then
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/actions/"$action" --
		else
			\curl -s \
				"${HEADERS[@]}" \
				"$API_URL"/config/actions \
				| \jq -c '.items[] | select(.name == "'"$action"'")' --
		fi
	else
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/config/actions --
	fi
}

show_tenant() {
	\curl -s \
		"${HEADERS[@]}" \
		"$API_URL"/auth/account/tenants --
}

generate_tokens() {
	res=$(
		\curl -s \
			"${HEADERS[@]}" \
			"$API_URL"/auth/refresh_tokens \
			-d '{"username": "'$1'", "password": "'$2'", "fingerprint": "svcp"}'
	)

	AUTH_TOKEN=$( jq -r '.refresh_token' -- <<< "$res" )
	ACCESS_TOKEN=$( jq -r '.access_token' -- <<< "$res" )
	
	if ! is_valid "$ACCESS_TOKEN"; then
		err "$res"
	fi

	HEADERS=( "${HEADERS[@]}" -H "Authorization: Bearer $ACCESS_TOKEN" )
}

delete_tokens() {
	\curl -s -X DELETE \
		"${HEADERS[@]}" \
		"$API_URL"/auth/refresh_tokens/"$AUTH_TOKEN" --
}

err() {
	msg="$1"
	\echo "${FUNCNAME[1]}: ${msg:-error call} at line ${BASH_LINENO[0]}"
	\exit 1
}

to_arr() {
	data=( "$@" )

	\tr '\n' ' ' <<< "${data[@]}" | \tr ' ' ' '
}

to_json() {
	arr=( "$@" )

	str=
	for i in "${arr[@]}"; do
		str+="\"$i\""
	done

	\sed 's/""/","/g' -- <<< "$str"
}

is_uuid() {
	[[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

is_valid() {
	[[ $( \base64 -di -- <<< "$1" 2>/dev/null >&1 | \jq -ce '""' -- 2>/dev/null >&1 ) ]]
}

main "$@"
