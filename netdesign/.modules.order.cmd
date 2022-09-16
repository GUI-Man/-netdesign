cmd_/home/jxy/netdesign/modules.order := {   echo /home/jxy/netdesign/my_dev.ko; :; } | awk '!x[$$0]++' - > /home/jxy/netdesign/modules.order
