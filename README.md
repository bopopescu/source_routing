# source_routing
这是实验室三专项源路由的测试的一些代码

##OpenvSwitch文件夹描述
这里有两个文件夹，一个是集成了ovs的mininet，还有一个是pox控制器</br>
进入mininet中的custon文件夹，启动拓扑
> cd mininet/custiom </br>
  sudo mn --custom source_route.py --topo mytopo --controller=remote,ip=127.0.0.1,port=6633 

进入pox文件夹，启动控制器，控制器脚本是ext文件下的ovs-forwad
> cd pox </br>
  sudo python pox.py openflow.of_01 --address=127.0.0.1 --port=6633 ovs-forward

##POF文件夹描述
这里有三个文件夹和两个.py文件，mininet-pof，是集成了pof的mininet，其中pof必须使用POFSwitch_Groups,PCTRL是控制器，其中source_route_test1_test2.py是第一个实验的拓扑，source_route_test3.py是第三个实验指标的拓扑。</br>
运行拓扑
> sudo python source_route_test1_test2.py 192.168.109.210(控制器ip地址)

运行控制器
> sudo python ./pox.py sr_ldy  openflow.pof_01 --port=6666 web pofdesk_v5
