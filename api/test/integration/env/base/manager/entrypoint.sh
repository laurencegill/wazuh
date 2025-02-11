#!/usr/bin/env bash

# Apply API configuration
cp -rf /tmp/config/* /var/ossec/ && chown -R ossec:ossec /var/ossec/api

# Modify ossec.conf
for conf_file in /tmp/configuration_files/*.conf; do
  python3 /tools/xml_parser.py /var/ossec/etc/ossec.conf $conf_file
done

sed -i "s:<key>key</key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" /var/ossec/etc/ossec.conf
sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" /var/ossec/etc/ossec.conf
sed -i "s:validate_responses=False:validate_responses=True:g" /var/ossec/api/scripts/wazuh-apid.py

if [ "$3" != "master" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
else
    cp -rf /tmp/configuration_files/master_only/config/* /var/ossec/
    chown root:ossec /var/ossec/etc/client.keys
    chown -R ossec:ossec /var/ossec/queue/agent-groups
    chown -R ossec:ossec /var/ossec/etc/shared
    chmod --reference=/var/ossec/etc/shared/default /var/ossec/etc/shared/group*
    cd /var/ossec/etc/shared && find -name merged.mg -exec chown ossecr:ossec {} \; && cd /
    chown root:ossec /var/ossec/etc/shared/ar.conf
fi

sleep 1

# Manager configuration
for py_file in /tmp/configuration_files/*.py; do
  /var/ossec/framework/python/bin/python3 $py_file
done

for sh_file in /tmp/configuration_files/*.sh; do
  . $sh_file
done

echo "" > /var/ossec/logs/api.log
/var/ossec/bin/wazuh-control restart

# Master-only configuration
if [ "$3" == "master" ]; then
  for py_file in /tmp/configuration_files/master_only/*.py; do
    /var/ossec/framework/python/bin/python3 $py_file
  done

  for sh_file in /tmp/configuration_files/master_only/*.sh; do
    . $sh_file
  done

  # Wait until Wazuh API is ready
  elapsed_time=0
  while [[ $(grep 'Listening on' /var/ossec/logs/api.log | wc -l)  -eq 0 ]] && [[ $elapsed_time -lt 120 ]]
  do
    sleep 1
    elapsed_time=$((elapsed_time+1))
  done

  # RBAC configuration
  for sql_file in /tmp/configuration_files/*.sql; do
    sqlite3 /var/ossec/api/configuration/security/rbac.db < $sql_file
  done
fi

/usr/bin/supervisord
