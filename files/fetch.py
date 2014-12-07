# this is a virtual module that is entirely implemented server side

DOCUMENTATION = '''
---
module: fetch
short_description: リモートからファイルを取得する
description:
     - このモジュールは M(copy) の様に動作しますがその逆になります。リモートマシンからファイルを取得し、ローカルのファイルツリーにホスト名付きで保存されます。このモジュールはログファイルの転送のためにあり、リモートの対象ファイルが存在せず fail_on_missing が 'yes' でなければエラーになる事に注意してください。
version_added: "0.2"
options:
  src:
    description:
      - 取得するリモートシステムのファイルです。これはディレクトリではなくファイルでI(なければなりません)。再帰的な取得は将来サポートされるでしょう。
    required: true
    default: null
    aliases: []
  dest:
    description:
      - 取得したファイルを保存するディレクトリです。例えば、I(dest) ディレクトリが  C(/backup) で、ホスト C(host.example.com) の I(src) が C(/etc/profile) であれば、C(/backup/host.example.com/etc/profile) に保存されます。
    required: true
    default: null
  fail_on_missing:
    version_added: "1.1"
    description:
      - ソースファイルが存在しない場合に失敗にします。
    required: false
    choices: [ "yes", "no" ]
    default: "no"
  validate_checksum:
    version_added: "1.4"
    description:
      - ファイルを取得したあとで、チェックサムが同じかチェックします。
    required: false
    choices: [ "yes", "no" ]
    default: "yes"
    aliases: [ "validate_md5" ]
  flat:
    version_added: "1.2"
    description:
      Allows you to override the default behavior of prepending hostname/path/to/file to
      the destination. dest が '/' で終われば、copy モジュールに似て、コピー元ファイルの basename になります。当然ファイル名がユニークであれば便利です。
requirements: []
author: Michael DeHaan
'''

EXAMPLES = '''
# ファイルを /tmp/fetched/host.example.com/tmp/somefile に保存
- fetch: src=/tmp/somefile dest=/tmp/fetched

# 保存先のパスを指定
- fetch: src=/tmp/somefile dest=/tmp/prefix-{{ ansible_hostname }} flat=yes

# 保存先のパスを指定
- fetch: src=/tmp/uniquefile dest=/tmp/special/ flat=yes

# playbook からの相対パスに保存
- fetch: src=/tmp/uniquefile dest=special/prefix-{{ ansible_hostname }} flat=yes
'''
