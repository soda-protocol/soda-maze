use crate::bn::BigInteger256 as BigInteger;
use crate::params::bn::Fr;

pub const FULL_ROUNDS: u8 = 8;
pub const PARTIAL_ROUNDS: u8 = 57;
pub const WIDTH: u8 = 3;
pub const SBOX: i8 = 5;

pub const ROUND_KEYS: &[Fr] = &[
    Fr::new(BigInteger::new([9492385987992791128, 680432315601848839, 2855872623209058572, 1601239780691047490])),
    Fr::new(BigInteger::new([6785711768592540442, 6246566044944926558, 125043130933818449, 1711334188322332030])),
    Fr::new(BigInteger::new([11889214640683519369, 12676343762103092894, 15630842739907632185, 1747563154250758156])),
    Fr::new(BigInteger::new([1781425799959376587, 5576951369229721360, 4579509650794976856, 1905804004543064714])),
    Fr::new(BigInteger::new([4967910043631949690, 4887120945351479534, 4903156736976941064, 1424614380430634974])),
    Fr::new(BigInteger::new([18163416886416750422, 10610031916305044256, 12376131412805926351, 2571763330952422576])),
    Fr::new(BigInteger::new([16036964197360354223, 2199185397879673735, 16115200014272331705, 2167034629478163220])),
    Fr::new(BigInteger::new([16312020987709640555, 150277992971307186, 14037448687886684307, 840753925044503264])),
    Fr::new(BigInteger::new([7974263260319809813, 12612301972148399635, 11100077495666911843, 2291946785910498863])),
    Fr::new(BigInteger::new([11072786811278892062, 15857476230623422101, 1902771322731444974, 2999019028533299606])),
    Fr::new(BigInteger::new([4701180530162667832, 16953402880492989363, 1902364378526638709, 1147697821055290789])),
    Fr::new(BigInteger::new([5502505977059079903, 12005536250375084262, 17512485249317180936, 548447162317232852])),
    Fr::new(BigInteger::new([15950994129402161894, 4476711956108625026, 858710511875970982, 2991386342463841204])),
    Fr::new(BigInteger::new([3472741239813896696, 17335412474294999322, 660354387833178050, 2171595159127769702])),
    Fr::new(BigInteger::new([3058701079828001029, 2890677029113198449, 1683308887457047629, 633057651583171474])),
    Fr::new(BigInteger::new([9129219381013658669, 15241099959342484620, 2912663340338322702, 2663525275108101203])),
    Fr::new(BigInteger::new([16294342951502932838, 11528743333027878635, 1990291069738282260, 889268533252338932])),
    Fr::new(BigInteger::new([17992601259104683587, 5574339285651952407, 14805212694841859769, 1055117261961357635])),
    Fr::new(BigInteger::new([1950798519110336717, 8738216843472981298, 4232044602529292455, 2867532395356886747])),
    Fr::new(BigInteger::new([14072074153131541578, 13466765647303294817, 17690949236245844164, 386303680763982558])),
    Fr::new(BigInteger::new([3738397943661022241, 16066661294110075930, 4388705872990474426, 1075448348766392601])),
    Fr::new(BigInteger::new([16453745958981549656, 5505720449011201667, 18125884272792593454, 3332257936799624513])),
    Fr::new(BigInteger::new([15102755707768561332, 376146962717109113, 1796448926039069290, 1781541050630821243])),
    Fr::new(BigInteger::new([15165650399746907255, 2705338612659828725, 4674506083352307222, 2349371282071926016])),
    Fr::new(BigInteger::new([6534694317512992079, 1049802161380986902, 1270026914422379959, 2884609713110715657])),
    Fr::new(BigInteger::new([7083829332371516362, 14744314301049375507, 8981193626533350650, 228696890086053443])),
    Fr::new(BigInteger::new([13755530019013931608, 9905333786591691619, 16916581038457154223, 2907167596399223765])),
    Fr::new(BigInteger::new([2836815395608359496, 1162849214241709289, 15637924693479086582, 2997013723792807195])),
    Fr::new(BigInteger::new([10874639921201471493, 1361387691435524309, 4607306715363025052, 1299241172059400563])),
    Fr::new(BigInteger::new([2474007637575010655, 11608790564506741353, 6833443574662758060, 1637766217708134366])),
    Fr::new(BigInteger::new([15231147020146148167, 4939934721696870667, 10070995726975861203, 1270047151218009016])),
    Fr::new(BigInteger::new([14937785022624509315, 14336737841571304003, 7954955362731906191, 588300739920358907])),
    Fr::new(BigInteger::new([1675272038689435087, 14491286059462361539, 13328379184518439410, 456139166978094564])),
    Fr::new(BigInteger::new([17428047754892482149, 12629480608578193262, 7611919350145998513, 1631338633219295205])),
    Fr::new(BigInteger::new([2846171152616721075, 2946666166289239251, 10022923544168554226, 1525382081908292015])),
    Fr::new(BigInteger::new([9413718024705677123, 5463718813552974845, 10730130612294759914, 3262267219296646124])),
    Fr::new(BigInteger::new([1371284375604075880, 6241663484501226644, 3694377333196890294, 2429025215152234401])),
    Fr::new(BigInteger::new([16967130559113956807, 6099407942124708799, 6562278094298763618, 2389842389746908648])),
    Fr::new(BigInteger::new([5477545236669482737, 1211762714528267598, 12169470690055892780, 1107842997905547349])),
    Fr::new(BigInteger::new([7556270343533115357, 2181509549463294067, 6404203279089162068, 795940158981058699])),
    Fr::new(BigInteger::new([1951454452575806217, 16152462803697083720, 10177034566237958875, 2468901478600654647])),
    Fr::new(BigInteger::new([11575892074822979000, 15116555357549375301, 13305173826181152069, 2907676788575409867])),
    Fr::new(BigInteger::new([1921370206945137508, 13319596580882363575, 827236922786842708, 2943207134884966246])),
    Fr::new(BigInteger::new([2448854893994041654, 13880939082779898024, 17550893478945596361, 600757975922844481])),
    Fr::new(BigInteger::new([11622158280406333939, 12826014912692808048, 3648758803192084365, 15523921996971884])),
    Fr::new(BigInteger::new([7341998920575910449, 4460486115513861843, 12230602338472618706, 963784706687916556])),
    Fr::new(BigInteger::new([5792913261297753604, 8676551811356064105, 6532668450158475600, 1946765936432159600])),
    Fr::new(BigInteger::new([3060598774615564569, 10694847644464400442, 16291214002778796475, 883592843458373219])),
    Fr::new(BigInteger::new([16743839663477790018, 10866719905869817779, 458023026390429012, 1274834315712071088])),
    Fr::new(BigInteger::new([969664360998917311, 5714584631582637421, 9932608885277513049, 3238653844654045218])),
    Fr::new(BigInteger::new([11748574660155781208, 9830152608154438925, 2252783248388741396, 3003101030549500709])),
    Fr::new(BigInteger::new([17022262168179194461, 4591939948646111082, 6902507678635218640, 550990660712380120])),
    Fr::new(BigInteger::new([6575222895915055470, 2181033120094307331, 9609166111161205417, 1222239067165053224])),
    Fr::new(BigInteger::new([2907369328178990645, 16229307983095172342, 10169900390190428538, 601902882389285782])),
    Fr::new(BigInteger::new([6163394434408436949, 2935725652278444915, 7479487501174099780, 2858507504554887596])),
    Fr::new(BigInteger::new([3648128518238149037, 2484118171856716275, 4161472687715281489, 1312957531634698882])),
    Fr::new(BigInteger::new([12527841453022086556, 3421871107944414050, 16996364101503174046, 246988419706918045])),
    Fr::new(BigInteger::new([3218457277626925512, 10889227037710429291, 8679748012095891144, 555195498767962676])),
    Fr::new(BigInteger::new([141047802431326450, 8819010469427358761, 12906950908615196878, 1084333900742853804])),
    Fr::new(BigInteger::new([15533803521246062311, 17104450110138381498, 9956797720697916600, 2935608942334322626])),
    Fr::new(BigInteger::new([18446389511817731004, 10303719460860111781, 7773017164297123373, 2303250225192302222])),
    Fr::new(BigInteger::new([2496848882172432493, 10059071162669401592, 6836344566827647538, 1410332897439271993])),
    Fr::new(BigInteger::new([12326489614629456032, 2850352237215691312, 11077142511904195158, 966074694685007886])),
    Fr::new(BigInteger::new([5678750025952036108, 9575874922646782889, 10286873734915683576, 3038833003119185102])),
    Fr::new(BigInteger::new([10319605252527893703, 12838725913791501712, 8100502034959115039, 1834106747466189177])),
    Fr::new(BigInteger::new([2454603565901187957, 11833002452855758484, 9768992809886367138, 188295862788215142])),
    Fr::new(BigInteger::new([163304208300370205, 6756543897366478359, 1911340653996774487, 1881548102183692104])),
    Fr::new(BigInteger::new([2223514717684822292, 15257208109305301504, 266699177487870105, 504945558167702649])),
    Fr::new(BigInteger::new([16234742846139171991, 11811321979898786225, 10331548084253177533, 1928009023669173947])),
    Fr::new(BigInteger::new([14936497687249233367, 6209344446139884622, 4558090797239379340, 2259651632802232724])),
    Fr::new(BigInteger::new([9421621255713088864, 14881362012402448524, 10541043939569887420, 1381622071738711635])),
    Fr::new(BigInteger::new([4557867218461602065, 13400854709613723048, 1756230101384651160, 151675050950634273])),
    Fr::new(BigInteger::new([3760270467451281712, 11307636880991605514, 7024442743162423361, 1605759728769491411])),
    Fr::new(BigInteger::new([11455984627500437363, 18080803636290950005, 5062453795801172136, 596607232926559247])),
    Fr::new(BigInteger::new([1297480227683359852, 10991706704671343910, 12073828502445968140, 1843544831108139002])),
    Fr::new(BigInteger::new([10263135176886829778, 2360546022943941508, 2128011834757315766, 3049089725953045146])),
    Fr::new(BigInteger::new([2095520126601598592, 1012650660287518294, 13785177310451783332, 42993062230293404])),
    Fr::new(BigInteger::new([5825184106633510496, 4981155365523313534, 13782380039928135187, 2855058821278377347])),
    Fr::new(BigInteger::new([2422092063936521858, 12023865292495703880, 4921509732105907343, 3354082069018549716])),
    Fr::new(BigInteger::new([11067535697941323019, 1597083831271585982, 5315612586192843418, 2321004217371776542])),
    Fr::new(BigInteger::new([1159270619709265003, 5800285925526351116, 1880622051169864128, 892695450846098685])),
    Fr::new(BigInteger::new([6340510174916572465, 2418547547568931707, 8278881626835178425, 2386704796502226413])),
    Fr::new(BigInteger::new([9116283479715616720, 16625831410307011934, 8106014213663818883, 723235213059443505])),
    Fr::new(BigInteger::new([268960373954320476, 8545489228044241917, 18235659211995804929, 1300704030102100822])),
    Fr::new(BigInteger::new([17159858480046309388, 13243933870202043742, 7030648860738788277, 1939629653051300265])),
    Fr::new(BigInteger::new([11551177797490254714, 6008210075956666550, 4676459225757489091, 2484572021505331156])),
    Fr::new(BigInteger::new([4218115909073274665, 13587287180935109255, 16748403983068171142, 3235736049255657928])),
    Fr::new(BigInteger::new([5779420765853774948, 7986130645005895850, 3859147274359273443, 2794492411602460987])),
    Fr::new(BigInteger::new([8685564408471301687, 17277825069652606908, 14374272093474342010, 4574722313233950])),
    Fr::new(BigInteger::new([1650241612506166310, 14582470972863714305, 16396461645646135410, 2419430364762850097])),
    Fr::new(BigInteger::new([15399017832735806103, 9662043588258498371, 8772289992687150415, 274679173109858506])),
    Fr::new(BigInteger::new([11282251135909189116, 9788096585216979374, 3253818946401113398, 1914228713935988857])),
    Fr::new(BigInteger::new([8401859072561506284, 680447676609925891, 5530663109336976197, 1887841671620191036])),
    Fr::new(BigInteger::new([9730158623796742825, 1765841029366783567, 11474897953255581298, 1248058104136715049])),
    Fr::new(BigInteger::new([827731767122986032, 2819051177996421369, 17123083023047877268, 521512650186406172])),
    Fr::new(BigInteger::new([6722831898932723684, 14976250812855784585, 15945264122790277069, 489051684197240849])),
    Fr::new(BigInteger::new([4178052325195943972, 9288563428295966241, 12764676135297010684, 1894045936683979341])),
    Fr::new(BigInteger::new([1804353356195542464, 11836834325569845050, 12836833472983472024, 2817615763346501482])),
    Fr::new(BigInteger::new([13884338014341132595, 2067654257431560717, 3836941909502851137, 779834429212070275])),
    Fr::new(BigInteger::new([6822408996772609321, 9052459740007257060, 13277931436803077858, 799475843607836910])),
    Fr::new(BigInteger::new([16566937307569276305, 1825241153925959833, 16202360976854424690, 2041596955263583318])),
    Fr::new(BigInteger::new([7549177869326321624, 11790855394740455767, 6663446786745290528, 2805112086378339507])),
    Fr::new(BigInteger::new([13046756337177552690, 11247190137901276084, 2652577541608437354, 145868346161471142])),
    Fr::new(BigInteger::new([15784197733371495856, 18340401071436017261, 6991271064696116536, 3183414350406304341])),
    Fr::new(BigInteger::new([17404545144690870677, 16059550041900800642, 6863407474927736536, 1020712365875236290])),
    Fr::new(BigInteger::new([8283702189939807512, 7033251390278024931, 15486674702186394271, 2385816946869394746])),
    Fr::new(BigInteger::new([15484346139889944978, 11061539063541902304, 13147294674244775444, 182421393942453431])),
    Fr::new(BigInteger::new([931833218763248069, 7412616766199752884, 2554440055639899180, 1115102548148101328])),
    Fr::new(BigInteger::new([9912403038280203282, 6667953813185467932, 8589040108216914607, 1460031738708179103])),
    Fr::new(BigInteger::new([428759828432979530, 16341262444306800656, 7041587980533932607, 1826216991068165871])),
    Fr::new(BigInteger::new([8558805171763539714, 17669286648835948788, 891679982460890062, 1259528723079006393])),
    Fr::new(BigInteger::new([8228021067736897828, 10203217282333935205, 12323541165411124101, 820014180158431402])),
    Fr::new(BigInteger::new([17545434236878316074, 4787706463226656798, 1506902758347851993, 1409218829218472132])),
    Fr::new(BigInteger::new([16236663252144844743, 15621140225070341260, 15290826579528008588, 1244799861482272611])),
    Fr::new(BigInteger::new([3223887781454563444, 17979877573659516942, 12867007760050148972, 2714778290228839572])),
    Fr::new(BigInteger::new([10285208291841527528, 6948780745214236321, 16526768694849230890, 41781808024986781])),
    Fr::new(BigInteger::new([441516302006632843, 2883228843878106679, 6047006886030983184, 899051016762392933])),
    Fr::new(BigInteger::new([2876313193578334798, 13625751456203409037, 17942922806834640867, 1336873836852714527])),
    Fr::new(BigInteger::new([15816576023562366228, 6394354159327420007, 8254913838401513564, 1118482827851062688])),
    Fr::new(BigInteger::new([16370549464928283356, 9017266233895940227, 6617002846045052946, 3084018464626681660])),
    Fr::new(BigInteger::new([13795227065728123492, 5674294324718673730, 11162138598013677948, 685805883257456337])),
    Fr::new(BigInteger::new([4715321237284089232, 6767327314124598694, 11030525607139273797, 461294083113434884])),
    Fr::new(BigInteger::new([9490151482744203676, 3669241485397417857, 1487910661867265899, 3221702104402901368])),
    Fr::new(BigInteger::new([6703013958294866884, 5740573599889139442, 9169000967940553391, 3253867364561092067])),
    Fr::new(BigInteger::new([15199618825473335872, 9638620524135769168, 7484658400452251951, 3046422369295734910])),
    Fr::new(BigInteger::new([18260016797947860154, 2413027391723436200, 8600813850640266027, 159859093693258763])),
    Fr::new(BigInteger::new([10744667470708648794, 12421208102378786176, 17153667325413167226, 2911968439518882795])),
    Fr::new(BigInteger::new([15402107643301744898, 10227711068321856503, 2912104992597667420, 1199551422994553472])),
    Fr::new(BigInteger::new([13210981064966798385, 10495919890841696882, 13858283242123073792, 371973900135966400])),
    Fr::new(BigInteger::new([15473631758161952423, 12780924759645306300, 14847564175774557219, 68338771027155605])),
    Fr::new(BigInteger::new([9816080153182492187, 17209877577610957999, 10237719122712381813, 2022592562179450833])),
    Fr::new(BigInteger::new([17548560868048021261, 6310699409140543668, 8782272207256381786, 2889457657918591490])),
    Fr::new(BigInteger::new([454509572197076662, 4036066963727863709, 9706051802717202499, 3195110380884334506])),
    Fr::new(BigInteger::new([4850587672217599031, 2432083970811581863, 14010428073529712024, 2585149040869456005])),
    Fr::new(BigInteger::new([11443066661239349489, 10395819359000603069, 8813387415210933670, 623518896489925140])),
    Fr::new(BigInteger::new([10266028125948613177, 14305217992117039299, 4332234152752093273, 147021229880785003])),
    Fr::new(BigInteger::new([14029535866112784496, 7603227790954774437, 9635606644501275201, 1248569553558705969])),
    Fr::new(BigInteger::new([15260239478562729213, 5245587421996122328, 15646809144087611082, 3139810032045668080])),
    Fr::new(BigInteger::new([5180094076789403264, 13094283231401970918, 11274055237589002583, 1081989954434433516])),
    Fr::new(BigInteger::new([13780125828256929282, 16346164960240820575, 5647379825225802883, 2291464843375300145])),
    Fr::new(BigInteger::new([14616347237877954777, 17757074611754590586, 8458456163180633921, 2030444081190172711])),
    Fr::new(BigInteger::new([4524437097570684517, 401441253725861593, 9512711603656442466, 2384309812434269113])),
    Fr::new(BigInteger::new([9132381749913871843, 13952267118475190265, 17357051174611373684, 1162528634753511853])),
    Fr::new(BigInteger::new([14355583159222375366, 15457736456737475753, 4978317235859798749, 3148475561072719848])),
    Fr::new(BigInteger::new([7729606933343298505, 219545460473071412, 8662475166097160388, 412691928210323081])),
    Fr::new(BigInteger::new([10856014889211278550, 1943141139499581774, 12507567488925814823, 2042713036568122184])),
    Fr::new(BigInteger::new([12662740357851334962, 7671484908582898700, 549571308008764814, 3257765016197599509])),
    Fr::new(BigInteger::new([15863018467112241852, 17644340520343327444, 6832443985131113865, 575554602935712387])),
    Fr::new(BigInteger::new([16433706509824394224, 689960980584058986, 11791101192535135297, 3291239584166721780])),
    Fr::new(BigInteger::new([4749073075314746601, 15765701355687054140, 11284023985673747358, 415026406868621459])),
    Fr::new(BigInteger::new([10067523271909037039, 11754847209678989028, 5206634709061971915, 2235099363165879342])),
    Fr::new(BigInteger::new([686653368916956376, 4475192364630420151, 18233462159935366919, 1948029977687835318])),
    Fr::new(BigInteger::new([9759994649110203867, 15124358328295788320, 4426745623989177207, 303163258775068378])),
    Fr::new(BigInteger::new([15390921800254587533, 15047922493350636393, 4721108941922146100, 1011584634256061285])),
    Fr::new(BigInteger::new([4343341054824596942, 6664152602522046471, 15383484986475705361, 1432577567517932509])),
    Fr::new(BigInteger::new([11976266449250722415, 14570208657183240744, 2727722481184199752, 706927110467693638])),
    Fr::new(BigInteger::new([8753456172221748441, 1928310587400448039, 8953084038383105929, 222723903120922772])),
    Fr::new(BigInteger::new([5698982850238941400, 7027596389076123291, 8788438897098804665, 3045209982984148313])),
    Fr::new(BigInteger::new([10615765454087019501, 17828181906921974498, 17054493997674651322, 360716835585969135])),
    Fr::new(BigInteger::new([3727845063630470122, 6466106027057660498, 1414225109441425084, 1583744692013741921])),
    Fr::new(BigInteger::new([15225393585896908386, 5059607403204495255, 1304858148419858590, 750218560544824365])),
    Fr::new(BigInteger::new([3211551279601294773, 16178187943088447160, 16116623574488029322, 1047298430350483948])),
    Fr::new(BigInteger::new([444450254458801874, 17778222950451824883, 9829207562596096793, 395369876646086642])),
    Fr::new(BigInteger::new([13568422239922907528, 4659131090850949357, 4096191643295078697, 2536596490995981361])),
    Fr::new(BigInteger::new([12844832520624277685, 1463375072122760280, 8418747747860765087, 3218265043389482223])),
    Fr::new(BigInteger::new([5850698880628604625, 9983947346297228204, 2442532681575046354, 1034858999536332965])),
    Fr::new(BigInteger::new([3047729673374908487, 6595226898304666666, 6091170354905526351, 407943507022233139])),
    Fr::new(BigInteger::new([3106545597355449234, 2290586979879927821, 1381365906847212028, 2767518665788131538])),
    Fr::new(BigInteger::new([3834372470841956509, 1891067200852382208, 15999174330944760386, 1854655987396631808])),
    Fr::new(BigInteger::new([323334831455602530, 2654489824306377851, 14490654422291532971, 2824767037648888516])),
    Fr::new(BigInteger::new([17346049557572124046, 9229138499144463966, 6463899025278637575, 2937468549304876880])),
    Fr::new(BigInteger::new([17720766353989911090, 5130498112782931254, 12530566427950548658, 3195739986985324144])),
    Fr::new(BigInteger::new([267964272551618455, 14181635912882132862, 14837027792144076604, 499560704270892084])),
    Fr::new(BigInteger::new([245923746708967933, 990160388023923063, 14631581084933872957, 846117560755338537])),
    Fr::new(BigInteger::new([9002492200107704519, 15404735335491462942, 3649167848143281501, 1736515108348153104])),
    Fr::new(BigInteger::new([8033832224964033986, 11217752499826234572, 6464771559658403142, 2748581007181225527])),
    Fr::new(BigInteger::new([1271648823112264521, 8542145596011310051, 9592808804924250648, 2052957147732784110])),
    Fr::new(BigInteger::new([12314498746854797229, 14852115978421790195, 3933627023155744415, 1333300876521270526])),
    Fr::new(BigInteger::new([13451956126854965446, 5300595935974163872, 18140023553826954924, 806742273274656804])),
    Fr::new(BigInteger::new([8344939040194919066, 18055233743815468804, 8392221776098422536, 1958554848971212640])),
    Fr::new(BigInteger::new([13019721829931584498, 5478177329019523671, 4326062303128257555, 1816510478549123036])),
    Fr::new(BigInteger::new([1900275542774399701, 13282679398350031482, 7904947510107908362, 1006766917953098601])),
    Fr::new(BigInteger::new([3176765308696596091, 3694932823379451923, 4776461991711220712, 1438663377964398024])),
    Fr::new(BigInteger::new([6399343004676677428, 8817320433172481532, 14116108683032283023, 2940593099472376148])),
    Fr::new(BigInteger::new([14815495968419637332, 12076648720354493093, 11928289111666646606, 921043718879137734])),
    Fr::new(BigInteger::new([6531872610264845178, 9603141938009148154, 6123730538301725408, 2479202428467222659])),
    Fr::new(BigInteger::new([7494210809494766355, 3966759493212263867, 5238638198371423428, 1545923789497686605])),
    Fr::new(BigInteger::new([10953990037883905676, 12576263051764481861, 255142733975182174, 1629640013065950860])),
    Fr::new(BigInteger::new([14427235524025007033, 11656913732441312018, 14189546752924297791, 1176881395896705690])),
    Fr::new(BigInteger::new([14012653313361960922, 557909367174609167, 17234364729622237997, 1628201886130546376])),
    Fr::new(BigInteger::new([663148339073337632, 8464402055788047042, 4927348323586189032, 2056135563463073262])),
    Fr::new(BigInteger::new([9572113627983184154, 7809839644435534867, 461081810604444660, 954858360498767757])),
    Fr::new(BigInteger::new([7324934142845805712, 15589035886627328827, 6448475038230785404, 1844701417372453901])),
    Fr::new(BigInteger::new([689401920670881259, 8211390969381428117, 16595533207974315115, 3081900775475391146])),
    Fr::new(BigInteger::new([5629252929866581284, 1745891308694971029, 8815899380953020205, 1021894107085760768])),
];

pub const MDS_MATRIX: &[&[Fr]] = &[
    &[
        Fr::new(BigInteger::new([17503398944334214103, 9230635622294457373, 15972181701675803672, 1035501513956951521])),
        Fr::new(BigInteger::new([3555859163746403433, 10741605658797293728, 13576548464965265343, 569316227345355306])),
        Fr::new(BigInteger::new([2951080920043055536, 4426455047811528265, 8768180898619925469, 274491192378258711])),
    ],
    &[
        Fr::new(BigInteger::new([7425745125907058133, 6258575766396631982, 6672317176208297581, 1888294593578598440])),
        Fr::new(BigInteger::new([17300927987635952711, 6895825125235677893, 7535349927233173892, 1004824698395431955])),
        Fr::new(BigInteger::new([3644467615925741357, 9640990985829502495, 7431090390984653628, 1714274394685692289])),
    ],
    &[
        Fr::new(BigInteger::new([14709430803763308375, 18229395017556423917, 14478888826236012152, 403155403580284040])),
        Fr::new(BigInteger::new([1681560448056422141, 2077804014413570479, 8164163776005235820, 19069250833956841])),
        Fr::new(BigInteger::new([5508715729952870696, 15229942319626936684, 5551071126244229286, 1333837310051341211])),
    ],
];