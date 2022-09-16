cmd_/home/jxy/netdesign/Module.symvers := sed 's/\.ko$$/\.o/' /home/jxy/netdesign/modules.order | scripts/mod/modpost -m -a  -o /home/jxy/netdesign/Module.symvers -e -i Module.symvers   -T -
