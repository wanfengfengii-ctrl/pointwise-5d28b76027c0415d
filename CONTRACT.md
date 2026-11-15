# HTTP/3留存中的QPACK受限采集配置

## 现有与新增

上游已经分离HTTP/3控制流及请求流；这里不解析QUIC、HTTP/3帧、网络或TLS。qcapture.Decoder目前只支持静态索引及静态名称引用，wire.py提供前缀整数与非Huffman字串解码。checks.py为原静态业务回归，须保留原断言。扩展同一API以支持下列完整受限配置；不能声称实现完整RFC9204，也无需Huffman或字节级反馈流编码。

Decoder(maximum,max_blocked)：maximum是至少32的非布尔整数，是整个连接的最大字节容量；max_blocked是正非布尔整数。动态表初始容量0，累计插入数0。maximum不因Set Capacity改变。单连接按调用顺序处理。

- header(stream_id,block)：stream_id为非负非布尔整数，每次新的header调用必须严格大于此前成功接纳的stream_id，block为≤65536字节的完整bytes头块。返回本次完成的[(stream_id,[(name_bytes,value_bytes),...]),...]。
- feed_encoder(chunk)：chunk为任意切分的bytes，单块≤32768字节；连续调用构成同一编码器指令流；只消费完整指令，残缺后缀保留到下次，返回因新指令完成的头块结果。
- cancel(stream_id)：丢弃仍阻塞的该头块并释放引用，已完成、未知或已取消ID无效果，返回[]。取消不回退最后接纳ID。stream_id必须非负非布尔整数。
- finish()：编码器无残缺指令且无阻塞头块时返回None，否则抛ValueError。成功finish之后不再接收新输入；除再次finish外的调用抛ValueError。

任何非法构造参数、指令、完整头块、越界引用、超限或finish截断均抛ValueError；实例一旦遇到输入/协议错误，后续所有方法均抛ValueError，不能输出看似有效的后续字段。输出保留字段顺序、重复字段及原始值字节，不做HTTP名称语义校验。除API明确限制外，值可以是任意bytes。

## 字节原语与静态表

前缀整数：首字节低p位为初值v，若小于2^p-1即结束；否则依次加上后续字节低7位×2^(7k)，高位0的字节结束。整数值不得大于2^31-1，本受限配置最多6个续字节，不另设最短编码要求。

字符串：H位+7位前缀整数长度+原始字节。所有Huffman标志必须为0；编码器及字段行中的字面名称也不支持Huffman。动态表项大小32+len(name)+len(value)，用字节数计。

本配置仅接收以下真实静态表下标，其它静态下标明确不支持并报错：0=(b':authority',b'')，1=(b':path',b'/')，17=(b':method',b'GET')，23=(b':scheme',b'https')，25=(b':status',b'200')。不要求补齐其它RFC静态项。

## 编码器指令

按首字节位模式识别（x为整数前缀位）：

- 1Txxxxxx：Insert With Name Reference，6位前缀整数i；T=1使用静态表i的name，T=0使用插入前相对动态索引i的name；随后一个字符串value。动态相对0为当前最新项。
- 01Hxxxxx：Insert Without Name Reference，5位前缀名称长度，H须0，随后name原始字节及一个字符串value。
- 001xxxxx：Set Capacity，5位前缀容量整数，不得超过maximum，必要时从最旧项起逐项逐出。
- 000xxxxx：Duplicate，5位前缀动态相对索引，复制插入前对应项的name/value，作为新的最新项。

每次Insert或Duplicate成功使累计插入数加1，赋给新项绝对序号1,2,...；逐出不复用序号。插入前必要时FIFO逐出，若新项自身超过当前容量，或所需逐出的最旧项仍被某个阻塞头块引用，须报错，不能越过它逐出较新的项。Duplicate及名称引用须在逐出前取值，但其原项同样可按规则逐出。Set Capacity也必须遵守阻塞引用保护。流中不出现真正需要超出2^31-1的累计插入数。

每条完整指令原子执行；不能因为前缀或字面字节尚未到齐先修改表、容量或累计数。执行一条指令后立即解阻塞所有已满足条件的头块并释放其引用，再处理同一chunk后面的指令，不能等chunk末尾才解阻塞。方法结果按相应头块header接纳顺序返回，不按ID大小之外另做字段排序。

## 头块前缀与绝对引用

头块以8位前缀整数Encoded Insert Count E开头，随后为S位+7位前缀整数Delta Base D。用该header接纳时的累计插入数T及整个连接maximum解码，之后冻结本块的R和Base，不能随未来插入重新解释。

M=floor(maximum/32)，F=2M；E=0则R=0。E>0时必须E<=F，令V=T+M，W=floor(V/F)*F，R=W+E-1；若R>V，则R<=F时报错，否则R-=F；R=0亦报错。S=0时Base=R+D，S=1时Base=R-D-1；Base不得为负。

R是本块所引用的最大动态绝对序号；纯静态/字面字段R必须为0，所有动态引用的最大序号必须恰为R。动态引用序号须大于0且不大于R；已经插入但已逐出的项不合法。对尚未插入的项保留引用，待指令流达到R后再还原。完整头块须在接纳时解析字段结构及全部索引，不能因为阻塞而忽略截断、Huffman标志或不合法整数；尚未插入项的name/value等到实际解阻塞时取值。

字段行位模式：

- 1Txxxxxx：Indexed，6位索引i；T=1静态i，T=0动态绝对Base-i。
- 01NTxxxx：Literal With Name Reference，4位索引i；T=1静态i的name，T=0动态绝对Base-i的name；随后字符串value。
- 001NHxxx：Literal With Literal Name，3位名称长度，H须0，随后name原始字节及字符串value。
- 0001xxxx：Indexed Post-Base，4位索引i，动态绝对Base+i+1。
- 0000Nxxx：Literal With Post-Base Name Reference，3位索引i，name取动态绝对Base+i+1，随后字符串value。

N位为never-index提示，0/1都接收但不改变输出。头块可以同时含前基索引、后基索引和字面名称，重复引用不得误增表容量。

R>T时头块阻塞，其已知和未来动态引用均受保护；超过max_blocked即报错。R<=T时当次header立即返回还原结果，不留下占位。取消阻塞块后，后续插入不得再返回它，且它释放的保护可使后续逐出合法。finish不得把未解阻塞当正常结束。

## 样例与资源

maximum=128，M=4：头块020080在T=0时解码R=1、Base=1并引用绝对1，先接纳应返回[]。编码器指令3f6141780161先把容量设为128，再插入(name=b'x',value=b'a')；完成插入时返回[(原stream_id,[(b'x',b'a')])]。将该指令任意切块结果不变。

状态只能保留当前动态表、尚未完成的编码器指令、尚未完成头块的描述/字面数据及固定计数；不得无限保存已完成或取消的块、已逐出条目或全连接原始输入。前缀整数解析可用有界累积器或未完成指令缓冲，不要求压缩当前合法大字面项；完整项受容量约束。

交付扩展实现、表/头块生命周期说明及独立短序列参照核验，覆盖前后基引用、相同chunk内解阻塞后逐出、计数回绕、Duplicate、容量缩减、取消释放、逐字节输入及错误后永久失败。给出长连接小表下的内存观察并核对真实字段，不用单条成功日志替代语义结果。.pointwise-runtime.json保留version=1、kind=cli，setup为准备argv列表，verify/demo各为单条argv；verify运行原静态回归及新增参照，demo展示先阻塞、字典到达后还原的实际字段和流ID。
