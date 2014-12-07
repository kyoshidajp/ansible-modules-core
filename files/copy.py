#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
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

import os
import time

DOCUMENTATION = '''
---
module: copy
version_added: "historical"
short_description: リモートにファイルをコピーする
description:
     - M(copy) モジュールはローカルのファイルをリモートにコピーします。リモートからローカルへファイルをコピーするには M(fetch) モジュールを使用します。
options:
  src:
    description:
      - リモートへコピーするファイルのローカルパスで、相対または絶対パスで指定します。パスがディレクトリであれば、再帰的にコピーされます。この場合、パスは "/" で終わり、ディレクトリの中身が転送されます。"/" で終わっていない場合、ディレクトリ自体がその内容とともにコピーされます。この動作は Rsync に似ています。
    required: false
    default: null
    aliases: []
  content:
    version_added: "1.1"
    description:
      - src の代わりに使用することで、ファイルディレクトリの内容を記述した値に設定します。
    required: false
    default: null
  dest:
    description:
      - リモートのファイルコピー先の絶対パスです。src がディレクトリであればディレクトリである必要があります。
    required: true
    default: null
  backup:
    description:
      - タイムスタンプ付きのバックアップファイルを作成します。この元ファイルからなんとかしてファイルを元に戻す事ができます。
    version_added: "0.7"
    required: false
    choices: [ "yes", "no" ]
    default: "no"
  force:
    description:
      - デフォルトは C(yes) で、コピー対象の内容が異なる場合に置き換えます。C(no) はコピー先に存在しない場合にのみコピーします。
    version_added: "1.1"
    required: false
    choices: [ "yes", "no" ]
    default: "yes"
    aliases: [ "thirsty" ]
  validate:
    description:
      - コピーを行う前に実行される検証コマンドです。検証を行うファイルへのパスは下の visudo の例のように '%s' を経由して検証するファイルのパスになります。コマンドは拡張のような機能があり、パイプは動作せず、セキュアです。
    required: false
    default: ""
    version_added: "1.2"
  directory_mode:
    description:
      - ディレクトリを再帰的にコピーする場合に使用します。このモードは新規に作成されたディレクトリにのみ設定され、すでに存在する場合は影響をあたえません。
    required: false
    version_added: "1.5"
extends_documentation_fragment: files
author: Michael DeHaan
notes:
   - copy モジュールの再帰的コピーは（100よりも）たくさんのファイルではスケールしません。選択肢として、rsync をラップした synchronize モジュールも検討してください。
'''

EXAMPLES = '''
# Ansible Playbooks の例
- copy: src=/srv/myfiles/foo.conf dest=/etc/foo.conf owner=foo group=foo mode=0644

# 上の例と同じですが、シンボリックモードで 0644 を指定
- copy: src=/srv/myfiles/foo.conf dest=/etc/foo.conf owner=foo group=foo mode="u=rw,g=r,o=r"

# 別のシンボリックモードの例で、パーミッションを一部変更
- copy: src=/srv/myfiles/foo.conf dest=/etc/foo.conf owner=foo group=foo mode="u+rw,g-wx,o-rwx"

# "ntp.conf" ファイルをバックアップしてコピー
- copy: src=/mine/ntp.conf dest=/etc/ntp.conf owner=root group=root mode=644 backup=yes

# "sudoers" ファイルを visudo で検査してからコピー
- copy: src=/mine/sudoers dest=/etc/sudoers validate='visudo -cf %s'
'''


def split_pre_existing_dir(dirname):
    '''
    Return the first pre-existing directory and a list of the new directories that will be created.
    '''

    head, tail = os.path.split(dirname)
    if not os.path.exists(head):
        (pre_existing_dir, new_directory_list) = split_pre_existing_dir(head)
    else:
        return (head, [ tail ])
    new_directory_list.append(tail)
    return (pre_existing_dir, new_directory_list)


def adjust_recursive_directory_permissions(pre_existing_dir, new_directory_list, module, directory_args, changed):
    '''
    Walk the new directories list and make sure that permissions are as we would expect
    '''

    if len(new_directory_list) > 0:
        working_dir = os.path.join(pre_existing_dir, new_directory_list.pop(0))
        directory_args['path'] = working_dir
        changed = module.set_fs_attributes_if_different(directory_args, changed)
        changed = adjust_recursive_directory_permissions(working_dir, new_directory_list, module, directory_args, changed)
    return changed


def main():

    module = AnsibleModule(
        # not checking because of daisy chain to file module
        argument_spec = dict(
            src               = dict(required=False),
            original_basename = dict(required=False), # used to handle 'dest is a directory' via template, a slight hack
            content           = dict(required=False, no_log=True),
            dest              = dict(required=True),
            backup            = dict(default=False, type='bool'),
            force             = dict(default=True, aliases=['thirsty'], type='bool'),
            validate          = dict(required=False, type='str'),
            directory_mode    = dict(required=False)
        ),
        add_file_common_args=True,
        supports_check_mode=True,
    )

    src    = os.path.expanduser(module.params['src'])
    dest   = os.path.expanduser(module.params['dest'])
    backup = module.params['backup']
    force  = module.params['force']
    original_basename = module.params.get('original_basename',None)
    validate = module.params.get('validate',None)
    follow = module.params['follow']

    if not os.path.exists(src):
        module.fail_json(msg="Source %s failed to transfer" % (src))
    if not os.access(src, os.R_OK):
        module.fail_json(msg="Source %s not readable" % (src))

    checksum_src = module.sha1(src)
    checksum_dest = None
    # Backwards compat only.  This will be None in FIPS mode
    try:
        md5sum_src = module.md5(src)
    except ValueError:
        md5sum_src = None

    changed = False

    # Special handling for recursive copy - create intermediate dirs
    if original_basename and dest.endswith("/"):
        dest = os.path.join(dest, original_basename)
        dirname = os.path.dirname(dest)
        if not os.path.exists(dirname):
            (pre_existing_dir, new_directory_list) = split_pre_existing_dir(dirname)
            os.makedirs(dirname)
            directory_args = module.load_file_common_arguments(module.params)
            directory_mode = module.params["directory_mode"]
            if directory_mode is not None:
                directory_args['mode'] = directory_mode
            else:
                directory_args['mode'] = None
            adjust_recursive_directory_permissions(pre_existing_dir, new_directory_list, module, directory_args, changed)

    if os.path.exists(dest):
        if os.path.islink(dest) and follow:
            dest = os.path.realpath(dest)
        if not force:
            module.exit_json(msg="file already exists", src=src, dest=dest, changed=False)
        if (os.path.isdir(dest)):
            basename = os.path.basename(src)
            if original_basename:
                basename = original_basename
            dest = os.path.join(dest, basename)
        if os.access(dest, os.R_OK):
            checksum_dest = module.sha1(dest)
    else:
        if not os.path.exists(os.path.dirname(dest)):
            try:
                # os.path.exists() can return false in some
                # circumstances where the directory does not have
                # the execute bit for the current user set, in
                # which case the stat() call will raise an OSError
                os.stat(os.path.dirname(dest))
            except OSError, e:
                if "permission denied" in str(e).lower():
                    module.fail_json(msg="Destination directory %s is not accessible" % (os.path.dirname(dest)))
            module.fail_json(msg="Destination directory %s does not exist" % (os.path.dirname(dest)))
    if not os.access(os.path.dirname(dest), os.W_OK):
        module.fail_json(msg="Destination %s not writable" % (os.path.dirname(dest)))

    backup_file = None
    if checksum_src != checksum_dest or os.path.islink(dest):
        try:
            if backup:
                if os.path.exists(dest):
                    backup_file = module.backup_local(dest)
            # allow for conversion from symlink.
            if os.path.islink(dest):
                os.unlink(dest)
                open(dest, 'w').close()
            if validate:
                if "%s" not in validate:
                    module.fail_json(msg="validate must contain %%s: %s" % (validate))
                (rc,out,err) = module.run_command(validate % src)
                if rc != 0:
                    module.fail_json(msg="failed to validate: rc:%s error:%s" % (rc,err))
            module.atomic_move(src, dest)
        except IOError:
            module.fail_json(msg="failed to copy: %s to %s" % (src, dest))
        changed = True
    else:
        changed = False

    res_args = dict(
        dest = dest, src = src, md5sum = md5sum_src, checksum = checksum_src, changed = changed
    )
    if backup_file:
        res_args['backup_file'] = backup_file

    module.params['dest'] = dest
    file_args = module.load_file_common_arguments(module.params)
    res_args['changed'] = module.set_fs_attributes_if_different(file_args, res_args['changed'])

    module.exit_json(**res_args)

# import module snippets
from ansible.module_utils.basic import *
main()
