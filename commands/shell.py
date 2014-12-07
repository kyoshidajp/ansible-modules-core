# There is actually no actual shell module source, when you use 'shell' in ansible,
# it runs the 'command' module with special arguments and it behaves differently.
# See the command source and the comment "#USE_SHELL".

DOCUMENTATION = '''
---
module: shell
short_description: ノードでコマンドを実行する
description:
     - M(shell) モジュールはスペース区切りのコマンド名をとります。まさに M(command) モジュールのようですが、リモートのシェル(C(/bin/sh)) でコマンドを実行します。
version_added: "0.2"
options:
  free_form:
    description:
      - shell モジュールは実行ための自由な form コマンドをとります。実際のオプション名は "free form" ではありません。例を参照してください。
    required: true
    default: null
  creates:
    description:
      - ファイルがすでに存在する場合、実行B(されません。)
    required: no
    default: null
  removes:
    description:
      - ファイルが存在しない場合、実行B(されません。)
    version_added: "0.8"
    required: no
    default: null
  chdir:
    description:
      - コマンドを実行する前にディレクトリに移動します。
    required: false
    default: null
    version_added: "0.6"
  executable:
    description:
      - コマンドを実行するシェルを変更します。絶対パスである必要があります。
    required: false
    default: null
    version_added: "0.9"
  warn:
    description:
      - no または false を指定すれば　警告を出しません。
    required: false
    default: True
    version_added: "1.8"
notes:
   - コマンドを安全で予想通りの実行とするために、代わりに M(command) モジュールを使用した方がよいかもしれません。Best practices when writing
   playbooks will follow the trend of using M(command) unless M(shell) is
   explicitly required. アドホックコマンドを実行する際は、自分にとってベストな方法を判断して使用してください。
   - shell モジュールの変数をサニタイズするには、"{{ var }}" の代わりに "{{ var | quote }}" を使って、セミコロンのような値を無視するようにします。

requirements: [ ]
author: Michael DeHaan
'''

EXAMPLES = '''
# リモートシェルでコマンドを実行する; 標準出力はリモートのファイルに出力される
 - shell: somescript.sh >> somelog.txt

# コマンドを実行する前に somedir/ にディレクトリを移動する
- shell: somescript.sh >> somelog.txt chdir=somedir/

# 'args' でオプションを指定することができる
# このコマンドは somedir/ にディレクトリを移動し、somedir/somelog.txt
# が存在しない場合のみ実行される
- shell: somescript.sh >> somelog.txt
  args:
    chdir: somedir/
    creates: somelog.txt
'''
