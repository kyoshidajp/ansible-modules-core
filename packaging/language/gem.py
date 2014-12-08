#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Johan Wiren <johan.wiren.se@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

DOCUMENTATION = '''
---
module: gem
short_description: Ruby gem を管理する
description:
  - Ruby gem のインストール、アンインストールを管理します。
version_added: "1.1"
options:
  name:
    description:
      - 管理する gem の名前です。
    required: true
  state:
    description:
      - gem の状態です。C(latest) は最新バージョンのインストールになります。
    required: false
    choices: [present, absent, latest]
    default: present
  gem_source:
    description:
      - インストールのソースとして使用するローカル gem のパスです。
    required: false
  include_dependencies:
    description:
      - 依存関係を含める、または含めないかです。
    required: false
    choices: [ "yes", "no" ]
    default: "yes"
  repository:
    description:
      - インストールする gem のリポジトリです。
    required: false
    aliases: [source]
  user_install:
    description:
      - ユーザのローカル gem キャッシュまたは全ユーザから gem をインストールします。
    required: false
    default: "yes"
    version_added: "1.3"
  executable:
    description:
    - gem を実行するパスを上書きします。
    required: false
    version_added: "1.4"
  version:
    description:
      - インストールまたは削除する gem のバージョンです。
    required: false
  pre_release:
    description:
      - リリース前のバージョンのインストールを許可するかです。
    required: false
    default: "no"
    version_added: "1.6"
author: Johan Wiren
'''

EXAMPLES = '''
# vagrant 1.0 をインストール
- gem: name=vagrant version=1.0 state=present

# rake の最新バージョンをインストール
- gem: name=rake state=latest

# rake のバージョン 1.0 をローカルの gem からインストール
- gem: name=rake gem_source=/path/to/gems/rake-1.0.gem state=present
'''

import re

def get_rubygems_path(module):
    if module.params['executable']:
        return module.params['executable'].split(' ')
    else:
        return [ module.get_bin_path('gem', True) ]

def get_rubygems_version(module):
    cmd = get_rubygems_path(module) + [ '--version' ]
    (rc, out, err) = module.run_command(cmd, check_rc=True)

    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', out)
    if not match:
        return None

    return tuple(int(x) for x in match.groups())

def get_installed_versions(module, remote=False):

    cmd = get_rubygems_path(module)
    cmd.append('query')
    if remote:
        cmd.append('--remote')
        if module.params['repository']:
            cmd.extend([ '--source', module.params['repository'] ])
    cmd.append('-n')
    cmd.append('^%s$' % module.params['name'])
    (rc, out, err) = module.run_command(cmd, check_rc=True)
    installed_versions = []
    for line in out.splitlines():
        match = re.match(r"\S+\s+\((.+)\)", line)
        if match:
            versions = match.group(1)
            for version in versions.split(', '):
                installed_versions.append(version.split()[0])
    return installed_versions

def exists(module):

    if module.params['state'] == 'latest':
        remoteversions = get_installed_versions(module, remote=True)
        if remoteversions:
            module.params['version'] = remoteversions[0]
    installed_versions = get_installed_versions(module)
    if module.params['version']:
        if module.params['version'] in installed_versions:
            return True
    else:
        if installed_versions:
            return True
    return False

def uninstall(module):

    if module.check_mode:
        return
    cmd = get_rubygems_path(module)
    cmd.append('uninstall')
    if module.params['version']:
        cmd.extend([ '--version', module.params['version'] ])
    else:
        cmd.append('--all')
        cmd.append('--executable')
    cmd.append(module.params['name'])
    module.run_command(cmd, check_rc=True)

def install(module):

    if module.check_mode:
        return

    ver = get_rubygems_version(module)
    if ver:
        major = ver[0]
    else:
        major = None

    cmd = get_rubygems_path(module)
    cmd.append('install')
    if module.params['version']:
        cmd.extend([ '--version', module.params['version'] ])
    if module.params['repository']:
        cmd.extend([ '--source', module.params['repository'] ])
    if not module.params['include_dependencies']:
        cmd.append('--ignore-dependencies')
    else:
        if major and major < 2:
            cmd.append('--include-dependencies')
    if module.params['user_install']:
        cmd.append('--user-install')
    else:
        cmd.append('--no-user-install')
    if module.params['pre_release']:
        cmd.append('--pre')
    cmd.append('--no-rdoc')
    cmd.append('--no-ri')
    cmd.append(module.params['gem_source'])
    module.run_command(cmd, check_rc=True)

def main():

    module = AnsibleModule(
        argument_spec = dict(
            executable           = dict(required=False, type='str'),
            gem_source           = dict(required=False, type='str'),
            include_dependencies = dict(required=False, default=True, type='bool'),
            name                 = dict(required=True, type='str'),
            repository           = dict(required=False, aliases=['source'], type='str'),
            state                = dict(required=False, default='present', choices=['present','absent','latest'], type='str'),
            user_install         = dict(required=False, default=True, type='bool'),
            pre_release           = dict(required=False, default=False, type='bool'),
            version              = dict(required=False, type='str'),
        ),
        supports_check_mode = True,
        mutually_exclusive = [ ['gem_source','repository'], ['gem_source','version'] ],
    )

    if module.params['version'] and module.params['state'] == 'latest':
        module.fail_json(msg="Cannot specify version when state=latest")
    if module.params['gem_source'] and module.params['state'] == 'latest':
        module.fail_json(msg="Cannot maintain state=latest when installing from local source")

    if not module.params['gem_source']:
        module.params['gem_source'] = module.params['name']

    changed = False

    if module.params['state'] in [ 'present', 'latest']:
        if not exists(module):
            install(module)
            changed = True
    elif module.params['state'] == 'absent':
        if exists(module):
            uninstall(module)
            changed = True

    result = {}
    result['name'] = module.params['name']
    result['state'] = module.params['state']
    if module.params['version']:
        result['version'] = module.params['version']
    result['changed'] = changed

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
main()
