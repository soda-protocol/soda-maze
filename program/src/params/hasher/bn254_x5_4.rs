use crate::bn::BigInteger256 as BigInteger;
use crate::params::bn::Fr;

pub const FULL_ROUNDS: u8 = 8;
pub const PARTIAL_ROUNDS: u8 = 56;
pub const WIDTH: u8 = 4;
pub const SBOX: i8 = 5;

pub const ROUND_KEYS: &[Fr] = &[
    Fr::new(BigInteger::new([4675466866566341926, 8698088188063495740, 10423897452055043101, 2502043820367835167])),
    Fr::new(BigInteger::new([15970049863210008936, 14618335249704749279, 14646544523058636394, 1351614311336215653])),
    Fr::new(BigInteger::new([16352076952239603906, 14382136972075372730, 12787003642804505031, 1547800992895504952])),
    Fr::new(BigInteger::new([10180112135564254806, 2653683156474060987, 2586519615287325201, 910593268905864060])),
    Fr::new(BigInteger::new([10852238621407333244, 1697086408515365427, 7820743496057054456, 3387000242759815631])),
    Fr::new(BigInteger::new([6339705589158790120, 9833952070573174304, 3376531369931022347, 239145008525577822])),
    Fr::new(BigInteger::new([7842059436005899754, 8451001155958025037, 15091820452290078219, 3264344975410033075])),
    Fr::new(BigInteger::new([7994221003452552626, 1821993276289525395, 5953893793293574764, 2621925035455593348])),
    Fr::new(BigInteger::new([9705844164105956390, 10271153131627644214, 5415632830405486764, 2487366355730407979])),
    Fr::new(BigInteger::new([2613034994837026435, 3482830836800884762, 9318715577843099962, 3382483285763538735])),
    Fr::new(BigInteger::new([3600605812704272163, 6503413699250318032, 1301608912089663556, 3440479665808568073])),
    Fr::new(BigInteger::new([15092038876759618770, 16040909454354802275, 12297215547725937274, 1405179991002813642])),
    Fr::new(BigInteger::new([8934472933572415542, 6719721021079730752, 13045191381372902644, 1335263375092123913])),
    Fr::new(BigInteger::new([12287052128038121247, 15241286732826095645, 1430651082550426209, 283103294603457686])),
    Fr::new(BigInteger::new([10353954467036661061, 7103595637071405673, 10029063298487553227, 2609128019099954502])),
    Fr::new(BigInteger::new([16988589646992050398, 18052809558027751237, 5952248095263696302, 1289713375429418410])),
    Fr::new(BigInteger::new([2036888176534116393, 7992347563817685625, 10407720256401910640, 1099295208963767384])),
    Fr::new(BigInteger::new([9889276204461820989, 15875578662876132567, 15191246536226694519, 3170353632264903259])),
    Fr::new(BigInteger::new([13221101211277898907, 3691266721064780581, 9009270547653619742, 1504964047022568108])),
    Fr::new(BigInteger::new([5952393981020602087, 16409373776235424790, 8896946933085802138, 789690020051100077])),
    Fr::new(BigInteger::new([17929329643106448994, 2178562124088306522, 3325922731318039145, 2074421009952958523])),
    Fr::new(BigInteger::new([2904573726878872131, 16099854507185521720, 11619758093777833116, 2595997938091441855])),
    Fr::new(BigInteger::new([9456898062391227971, 17789689569412366233, 10583928932451965215, 2239674936182015326])),
    Fr::new(BigInteger::new([2248997874511374492, 4154218601982371184, 9192151029109736503, 2600083043789041669])),
    Fr::new(BigInteger::new([9435305196137418661, 1563106900151794655, 13222496682837246715, 595434086267080925])),
    Fr::new(BigInteger::new([7926706882520148651, 3782614734060301867, 3416630137281475412, 1307295748979130567])),
    Fr::new(BigInteger::new([11982488579100629651, 17050626305855652633, 17932785236783403568, 2309115186122651623])),
    Fr::new(BigInteger::new([4534716499133680670, 12995666419826378823, 12482377756809610985, 10310827752873776])),
    Fr::new(BigInteger::new([5077654988117387532, 10837282511426998375, 5162720882305015957, 362635235491009441])),
    Fr::new(BigInteger::new([16838001333020950485, 7485503096357031832, 5912577748546205787, 3462552577430399184])),
    Fr::new(BigInteger::new([16187295899036271129, 13689872542391194485, 1293162941391076836, 2013305793145607880])),
    Fr::new(BigInteger::new([1729810271586362915, 2154709790628977564, 9181729317342738665, 2951101519090550143])),
    Fr::new(BigInteger::new([4234953590438737643, 4608514614999268141, 16189639032285982450, 2631398312266731854])),
    Fr::new(BigInteger::new([12001225271515054673, 10401708067601581912, 16049260428015536890, 2305642863193908559])),
    Fr::new(BigInteger::new([13864264444873516081, 3807609839879860099, 3762122850645306859, 3065232893849497657])),
    Fr::new(BigInteger::new([15395138045945116620, 15397795047587608707, 10028387355633507616, 1159735764597579712])),
    Fr::new(BigInteger::new([5835104926781093685, 15585089663698637329, 8898596437902971979, 1837026166096270756])),
    Fr::new(BigInteger::new([7971883872632644721, 5662739353461263047, 17090912075062571707, 2881093656559334227])),
    Fr::new(BigInteger::new([12100650173351017524, 17510352985846179346, 11242237976870483499, 3168893066668710930])),
    Fr::new(BigInteger::new([16666699072603136728, 1563589135459593375, 9148097045768864601, 2747831758964580421])),
    Fr::new(BigInteger::new([18368643120167647622, 2447905787975006492, 5122211567780362534, 1157067869999873939])),
    Fr::new(BigInteger::new([1309042410312200710, 5920846034877812718, 5024087607439180224, 2677738328059737654])),
    Fr::new(BigInteger::new([10623803500509464747, 8074338415077761228, 15015637738721613943, 2479453427281788075])),
    Fr::new(BigInteger::new([2061316424175068186, 13915195389610240461, 17844548991263379209, 237345695620586598])),
    Fr::new(BigInteger::new([2161247060085145907, 2229336357673334682, 1286895427368489582, 1704707863980124142])),
    Fr::new(BigInteger::new([404798588033632166, 14770381814244572028, 2293915436654065970, 886332053796200110])),
    Fr::new(BigInteger::new([4814571197724368142, 8748643194920286527, 6605849187513926027, 2965979379117675842])),
    Fr::new(BigInteger::new([4802316355234105755, 8063532827131888522, 2685433767963550567, 2179686700060284989])),
    Fr::new(BigInteger::new([12105520036857324678, 8431242165737723328, 3246596211958133247, 42451468091666959])),
    Fr::new(BigInteger::new([8690857546876003833, 5948383252314235996, 10188373130043337528, 2762005925268006677])),
    Fr::new(BigInteger::new([8600571335037901033, 15247506756604628117, 7541141448903228743, 3302633039934061542])),
    Fr::new(BigInteger::new([11337776863871932602, 2689982049234922319, 18059894771620424396, 2015441083788061745])),
    Fr::new(BigInteger::new([3631247679644875958, 13108288854571979895, 9344027328585163592, 1901426088985278486])),
    Fr::new(BigInteger::new([2627741284440874474, 3496894443763473382, 4223904558847320478, 493379475325464035])),
    Fr::new(BigInteger::new([14389015049385860169, 491386590552767523, 18257744757821428072, 2516296448494571386])),
    Fr::new(BigInteger::new([14561379855616543293, 8512924057508807862, 11577567069911570672, 3065645381426477791])),
    Fr::new(BigInteger::new([3744156902755767747, 6113215441818632595, 11618923964910459801, 1927937837850729980])),
    Fr::new(BigInteger::new([6320807197844437723, 17648721265231900766, 3916674192046462294, 2775360746343999797])),
    Fr::new(BigInteger::new([14669779938178187713, 15132934777461215543, 16215792632301861615, 3454232862955434379])),
    Fr::new(BigInteger::new([6275320088495512101, 10831628026951708133, 16187008359898903862, 2125010333028224505])),
    Fr::new(BigInteger::new([10760951978549122905, 2241036254978217577, 9879303485968186226, 2716210685366419761])),
    Fr::new(BigInteger::new([2869177808117327886, 5954103488115093867, 11962285843409240279, 2863718555402728300])),
    Fr::new(BigInteger::new([1256316649793195981, 4465620821515137638, 17567710889065425459, 1639764839462023609])),
    Fr::new(BigInteger::new([7410683741343860654, 15257751173547932907, 14964262179165471422, 411464048555421247])),
    Fr::new(BigInteger::new([3203204262882302714, 9256080387923199787, 12346346974304289162, 2899555690085393839])),
    Fr::new(BigInteger::new([15281231561022895801, 2752741218887185059, 13298691972562833654, 2293242177421529868])),
    Fr::new(BigInteger::new([10931488528421286134, 1475225488352426940, 6053031722976842788, 3236670436417482336])),
    Fr::new(BigInteger::new([7389365566659925888, 4883530168347506768, 5725687597548128738, 2772555444345320178])),
    Fr::new(BigInteger::new([12719851745021852427, 8196038954393554486, 16623048700019906980, 194592401379876282])),
    Fr::new(BigInteger::new([403040102376791231, 18122699519245443001, 15764320848897810561, 1878483909480221002])),
    Fr::new(BigInteger::new([17581741660774449085, 3323300470878660019, 16348147379493610896, 612676135603479378])),
    Fr::new(BigInteger::new([8205376593495346432, 9140977420710894896, 17007036241670317333, 1801281367993957685])),
    Fr::new(BigInteger::new([15299313557707301818, 1429669073366050265, 7531717604422844274, 68467991208360455])),
    Fr::new(BigInteger::new([1036008553861173057, 266050086424066720, 5511532436734522177, 1412976668380633536])),
    Fr::new(BigInteger::new([11449394777525962627, 5440584646878322781, 16252710310131369744, 115182428716166459])),
    Fr::new(BigInteger::new([11609977187769543663, 16104973290426870689, 12791418873489221411, 1065876331953191892])),
    Fr::new(BigInteger::new([2362762019741829290, 10178838880123547871, 4033150107356591077, 2811652043286702395])),
    Fr::new(BigInteger::new([817300050578989482, 13095603270499017194, 2079465774347706540, 1156091692880578734])),
    Fr::new(BigInteger::new([10411864162576990148, 6294376514038413675, 3423275996578188615, 2313896988615976435])),
    Fr::new(BigInteger::new([7930028134262863336, 1950043326159030190, 8645228919780477877, 983316236370098384])),
    Fr::new(BigInteger::new([16371192481501122352, 13302010115073501498, 3884896328725390769, 2827687379753852960])),
    Fr::new(BigInteger::new([11832823934260790609, 9589478877085173476, 14015262340877929568, 2206888137365810790])),
    Fr::new(BigInteger::new([7000321553410302452, 5365869424768579377, 8376362150715149844, 401484162793260172])),
    Fr::new(BigInteger::new([8832122980397905057, 18367449426408408283, 8838258159702026930, 2554117326051723165])),
    Fr::new(BigInteger::new([5046992882849828407, 15965069868160778325, 4658702759084324217, 2234906852753817116])),
    Fr::new(BigInteger::new([811739470977140461, 5174209401619716859, 13399112132416840061, 1721779741330351766])),
    Fr::new(BigInteger::new([13208234432231314841, 5473961587384358114, 18358867688942299128, 1746216531190028970])),
    Fr::new(BigInteger::new([7107333277001452504, 11850504399338440795, 4018917279324384109, 2294822818314673971])),
    Fr::new(BigInteger::new([8481374630816952318, 9135566968146740037, 7658391607597085612, 3443449736376385464])),
    Fr::new(BigInteger::new([16981016919028396055, 15827237827476987886, 6310349406399804872, 2679221185858081638])),
    Fr::new(BigInteger::new([7679791368289582080, 5401213054580534319, 3643816270080727291, 564839669209242026])),
    Fr::new(BigInteger::new([6444915406586353495, 9164871161402563748, 553645336507784209, 1034588710929684839])),
    Fr::new(BigInteger::new([14140738798542625150, 10707986700451562015, 8145897737123984167, 3337620430273556485])),
    Fr::new(BigInteger::new([8376374427389357064, 13598932075499719388, 15638026992214629534, 1157696992794412131])),
    Fr::new(BigInteger::new([7417372841495901704, 11277925501064583002, 10592110712756595669, 1695579541827231758])),
    Fr::new(BigInteger::new([3946230718813362049, 16307904054987872663, 10395029835119230854, 148504839781715269])),
    Fr::new(BigInteger::new([2138113323141074945, 5899011690524720291, 7924741334761380750, 3059654371749060995])),
    Fr::new(BigInteger::new([9540526306612898748, 2551013959541967678, 2094330684312829133, 1838289386847089744])),
    Fr::new(BigInteger::new([9201615107020722972, 8812912552312748670, 18193334819970645438, 2806344276883228037])),
    Fr::new(BigInteger::new([5383788703326619491, 10303796115738533721, 18326304957897068380, 2125307612169833294])),
    Fr::new(BigInteger::new([6845335852726821084, 8136636683516579280, 13237423853905288084, 446203256938223347])),
    Fr::new(BigInteger::new([16242235800708725871, 17013723615897523835, 8641588522689197754, 986607413658872452])),
    Fr::new(BigInteger::new([4721140960137719694, 14625279630955983765, 9770330921097958922, 1191459684917745410])),
    Fr::new(BigInteger::new([2022823871947239355, 11616289519116504017, 14716783086315045561, 425622600473061848])),
    Fr::new(BigInteger::new([7924161253345802013, 11563391674631155163, 6134420938220778577, 1007659548157875783])),
    Fr::new(BigInteger::new([11217220897080345137, 14736006592807132304, 1014479041500164676, 1653067672896082544])),
    Fr::new(BigInteger::new([2320161857470827747, 3717911535857415607, 4618489721633837643, 2956839800549383642])),
    Fr::new(BigInteger::new([2789181257413435428, 12015808745328833960, 1886330798458646844, 1060837316997496716])),
    Fr::new(BigInteger::new([11605672451783309586, 17828202307451901346, 10398972150881632786, 946401431955720691])),
    Fr::new(BigInteger::new([1257740855991524504, 4485702132034866325, 82976391237609224, 1716033879252496530])),
    Fr::new(BigInteger::new([9230973785763751977, 11579601537643257616, 15181300742445069201, 2755567555987306158])),
    Fr::new(BigInteger::new([15682902211639444665, 7711830609159191726, 10619287133739067589, 413152483628098661])),
    Fr::new(BigInteger::new([1321285918450889243, 480422772638756472, 16707062400043939567, 1992924724054066904])),
    Fr::new(BigInteger::new([18249659748961583627, 434455714657880611, 1286200091080042771, 856900029412569800])),
    Fr::new(BigInteger::new([237175404087360200, 3285349101972080343, 18426481481641555472, 150321141532897827])),
    Fr::new(BigInteger::new([18329788926722287163, 4318266095006878681, 454073439929929434, 171067709377739245])),
    Fr::new(BigInteger::new([2157466980395678105, 11917885820506753571, 6969006850005098444, 1869301148086363161])),
    Fr::new(BigInteger::new([9137117528114793450, 3436365556429088915, 5528414699760560397, 1758743620308275060])),
    Fr::new(BigInteger::new([9047268428510344201, 13084003311941634777, 12795362283493376364, 2895964030400832603])),
    Fr::new(BigInteger::new([3127405375747206094, 8526307578843796792, 15924866985828047234, 1793210539918305594])),
    Fr::new(BigInteger::new([1476852171664806531, 9851808471483998789, 6406831429691067848, 980114815380761738])),
    Fr::new(BigInteger::new([11566939969923227553, 8119770622171679431, 10040134349481417933, 3409758726395341978])),
    Fr::new(BigInteger::new([9445249079892800084, 15605621794890929588, 7622621196450194284, 2155039731085922553])),
    Fr::new(BigInteger::new([15945746511587014068, 16662748989639654099, 3666806754789876097, 2116017553724868267])),
    Fr::new(BigInteger::new([14066169132783176285, 4608073477214709904, 6857211810914013897, 481738902695647539])),
    Fr::new(BigInteger::new([11224677793112495972, 6693179037536004135, 3549557639596414498, 2659105688351328297])),
    Fr::new(BigInteger::new([4355212856104528943, 16090705276966989817, 8053692844354238137, 1214489000688363547])),
    Fr::new(BigInteger::new([4960395557022704728, 11388456897015366231, 6664718552923660911, 1179172273263976363])),
    Fr::new(BigInteger::new([17546630318853949738, 13106276634945074354, 16715233591372628358, 3345152956676036929])),
    Fr::new(BigInteger::new([10543788576410855145, 1962951594842376199, 4134746624714915518, 52759995228680474])),
    Fr::new(BigInteger::new([11696532590015654821, 18282729119811275133, 11722159705709105700, 1636404818369792859])),
    Fr::new(BigInteger::new([5371228029776229148, 16697010283146040468, 4075488064719780081, 3120650830810037940])),
    Fr::new(BigInteger::new([17443732154770311612, 7990947798427819550, 15463744537085842660, 1992935361386297440])),
    Fr::new(BigInteger::new([11116715889846001127, 1038311721067088527, 13140382074047415890, 685772820937208468])),
    Fr::new(BigInteger::new([13315271840163260028, 17008472076778556357, 8037025886449830581, 2294149870586830752])),
    Fr::new(BigInteger::new([6971807714675991720, 5865379377169066010, 11974097400193372187, 2775778181271995131])),
    Fr::new(BigInteger::new([1471304926738642559, 16033644233199661547, 11348674713036326491, 1603188615243119645])),
    Fr::new(BigInteger::new([7385173070873245203, 16420219670954126986, 2767569906637643831, 1599925175312085903])),
    Fr::new(BigInteger::new([13632134145099137827, 15375468656087641658, 17200515778088748784, 662090183156020651])),
    Fr::new(BigInteger::new([15449478953765783702, 14153652587969350806, 14343691896384725781, 1703597332973292159])),
    Fr::new(BigInteger::new([10265591059912396469, 9462422765103411520, 3716086411434332243, 1588783412613106849])),
    Fr::new(BigInteger::new([13031283914760499772, 8482222122861480050, 15411369094456163427, 1613172826808465607])),
    Fr::new(BigInteger::new([16724800649643438085, 13049081699104342353, 5813387145284945663, 2677096250201232703])),
    Fr::new(BigInteger::new([10923895059591184886, 3625597008365176467, 1019246181093233820, 134361234976140624])),
    Fr::new(BigInteger::new([4479555253713702671, 4191777278358267537, 5464285941149599926, 705548271160269669])),
    Fr::new(BigInteger::new([1141961523849036918, 16779309712983283330, 14868439164349089174, 1672629440395165759])),
    Fr::new(BigInteger::new([16224370841119379629, 7283276983322104108, 13717987539379501651, 1824098482422287311])),
    Fr::new(BigInteger::new([4455387088704890915, 13007600836051174177, 3980210250334390838, 1680502920011204316])),
    Fr::new(BigInteger::new([7556310243441198225, 7290623909922297567, 17606226989741610677, 466131126974531455])),
    Fr::new(BigInteger::new([17034469016117585421, 1021265006275357751, 472743019695208788, 2072619835123509897])),
    Fr::new(BigInteger::new([7036638058738392785, 11216654697384255235, 5838044253239817207, 2358106627211056352])),
    Fr::new(BigInteger::new([3076852931679053045, 16508113424631881813, 5080758007797973083, 1845981248968892494])),
    Fr::new(BigInteger::new([16584009282255736696, 15701687325602663820, 12307263570834531273, 1979547200677519506])),
    Fr::new(BigInteger::new([6730248531986954010, 17726241564446986093, 15401041704463097735, 835005879838405286])),
    Fr::new(BigInteger::new([13764751469286818649, 16008876683598174344, 2858610143148451310, 1492961218596904091])),
    Fr::new(BigInteger::new([9570781281283423471, 13682550611778750134, 3883076539612930720, 3409958804964775152])),
    Fr::new(BigInteger::new([6268756931956181878, 17458542988313656830, 18110176078257062474, 2698619361970079876])),
    Fr::new(BigInteger::new([10109127938331565582, 14265059882749075906, 13760205264269527764, 2683367360917144650])),
    Fr::new(BigInteger::new([7008952481098960460, 11104923070074747434, 4564813599807178049, 1232136470673725495])),
    Fr::new(BigInteger::new([15079272740896282192, 91682687919969136, 3385859973554054467, 185813749835111864])),
    Fr::new(BigInteger::new([7428731288939905273, 6594961261612938909, 1860940572045260906, 1816104498833346124])),
    Fr::new(BigInteger::new([12205450138379448632, 14206842871790450058, 3320707091751152242, 3244716501183552833])),
    Fr::new(BigInteger::new([10867382360579723401, 8685006470696129386, 11349479887044448088, 2882615965564415589])),
    Fr::new(BigInteger::new([17430554440063171768, 13354659464867092323, 684112173113848762, 2103708265562645544])),
    Fr::new(BigInteger::new([16092589220191765837, 2889224895982494944, 10698248762256473720, 65086164828917028])),
    Fr::new(BigInteger::new([13031096720514199688, 9493534053448658006, 4323430331744606658, 1988316819999280007])),
    Fr::new(BigInteger::new([5516402462904048142, 325466687578395100, 3413204764165659082, 2448457282519771086])),
    Fr::new(BigInteger::new([1118883349778409103, 4576270473593675931, 2964124913127128458, 3459952807266879055])),
    Fr::new(BigInteger::new([2818928682116959409, 14631651357913702647, 6663948112145557312, 1003838442335455035])),
    Fr::new(BigInteger::new([390337917417714045, 7453274081389055893, 11326172871706098739, 2336730919511680731])),
    Fr::new(BigInteger::new([3219930482827215436, 3577022440822708278, 17081971390560702034, 534103466270164896])),
    Fr::new(BigInteger::new([13499618240480997704, 5885752850376732799, 5993511711864540875, 2506783973789363285])),
    Fr::new(BigInteger::new([10020998588861250008, 9619111806957364793, 7010684602332280929, 892502051734363604])),
    Fr::new(BigInteger::new([5835235392211568679, 515928793144236691, 16118515778525298061, 1920874288009627394])),
    Fr::new(BigInteger::new([11568743827632695727, 14662022861828556668, 18371251405253208995, 2190911315260323405])),
    Fr::new(BigInteger::new([2655054075237384552, 8134047393251346235, 13515216370569822199, 1010061060152177843])),
    Fr::new(BigInteger::new([15851923944598673517, 15403244540150523611, 14614456627265649505, 1734930288354193641])),
    Fr::new(BigInteger::new([1199528126637166661, 14476900563754895118, 7168985810985781386, 2723687866702256075])),
    Fr::new(BigInteger::new([12226905554634842952, 4684964275068104157, 6054449593150703493, 164803088529682148])),
    Fr::new(BigInteger::new([2554039228838283424, 15054315143760390134, 11006170250731364146, 2989974533017269977])),
    Fr::new(BigInteger::new([3406991261013331961, 15665276598773190450, 1361493305047425345, 462398668967920549])),
    Fr::new(BigInteger::new([5252925685744052240, 7096063300474085847, 16988452013727589580, 1857659857944787591])),
    Fr::new(BigInteger::new([7958214902854215152, 17397209091260565076, 12203541901652892840, 287186552451136943])),
    Fr::new(BigInteger::new([454369483877033768, 12932804581165512065, 14588392264992319135, 2856134363531918941])),
    Fr::new(BigInteger::new([15942413314514763728, 8785903915973040810, 5908888107057198664, 572465552325487188])),
    Fr::new(BigInteger::new([14414250118399006243, 8805564236096323555, 2844441889792411514, 794706959764016081])),
    Fr::new(BigInteger::new([2750662921232897240, 7003136265380781439, 11144430514647703295, 1892112852698022915])),
    Fr::new(BigInteger::new([15309389744400074720, 18038284691728808342, 6549231199218798586, 2972594018614545909])),
    Fr::new(BigInteger::new([1262523788437147131, 3419855652774249019, 9528823021918117938, 2853144957400705442])),
    Fr::new(BigInteger::new([10700024945012418315, 5938153561165626877, 15311563687305212769, 3182124382030585874])),
    Fr::new(BigInteger::new([496652656010274598, 16598396872689501718, 533982047397414654, 2190888260606486130])),
    Fr::new(BigInteger::new([2603814546916715700, 15674550920861745408, 16764426190505170256, 1642317281362335527])),
    Fr::new(BigInteger::new([5700615078566252958, 8134475246895646203, 5127175569953893820, 2732116827909026543])),
    Fr::new(BigInteger::new([9315313305530762450, 9857808781865459039, 5735740649837755572, 1936365215713376838])),
    Fr::new(BigInteger::new([11618939481904593082, 16497254870622848946, 7974804236128461928, 2860542960560656714])),
    Fr::new(BigInteger::new([11267769766703741990, 1241494418766186414, 13201924482570703206, 969652823561317758])),
    Fr::new(BigInteger::new([17424750888960818266, 12747959549943050599, 15033161604355185744, 469845580027904208])),
    Fr::new(BigInteger::new([2572997978768653192, 10800687432704220629, 7996369278172654376, 2356585457099915016])),
    Fr::new(BigInteger::new([8965480501456866441, 15664224811814510187, 18253147861406097496, 3293490479524220289])),
    Fr::new(BigInteger::new([7335579806034862219, 12959949693581497823, 12712686103049843051, 2105493719989743862])),
    Fr::new(BigInteger::new([2114282885818780885, 385621311062112971, 8171379691612328365, 223852065572751756])),
    Fr::new(BigInteger::new([12251719385779462152, 9661326860738292638, 3196075047317811645, 2476567736962759058])),
    Fr::new(BigInteger::new([6247904640748168802, 14568131285259442160, 13283176773610304183, 3105088466939724113])),
    Fr::new(BigInteger::new([17966089470311322486, 8968741351669590017, 4909198506671462900, 2084346925026086097])),
    Fr::new(BigInteger::new([8183785313322333472, 13822814217780606437, 3750682931732220911, 2287167716235868171])),
    Fr::new(BigInteger::new([12008452296370302344, 1965523875853992333, 14166405570351513612, 245670402031735457])),
    Fr::new(BigInteger::new([6209391076700894643, 2390259561405138106, 9285897024427040552, 2806799770453254929])),
    Fr::new(BigInteger::new([12483493624514793206, 17686982611265781618, 3502181670600577416, 1103415855434154646])),
    Fr::new(BigInteger::new([501550571791208976, 3672099229650168432, 15768638169328145233, 1594350025030393233])),
    Fr::new(BigInteger::new([16120798353980100097, 5333766467606033659, 5288017618957943028, 719757400333196420])),
    Fr::new(BigInteger::new([6306474950119160828, 2907043175953569589, 5204491955573938168, 338083566685373646])),
    Fr::new(BigInteger::new([8195269671212957446, 7331920247836274328, 7380163430861418169, 2388761508462269189])),
    Fr::new(BigInteger::new([9968798823118605468, 17127895202550741099, 2562702444742487698, 614422811259048927])),
    Fr::new(BigInteger::new([6877824898103080689, 598608423755047121, 181307991318232672, 3425680489082762623])),
    Fr::new(BigInteger::new([12345324672124253283, 8072313451800117889, 197850250313574054, 2811615666774259859])),
    Fr::new(BigInteger::new([16685154668598613784, 16492323379937199226, 14383132795784735433, 2550116725558779653])),
    Fr::new(BigInteger::new([12902481038855919704, 15094799257335966523, 1798376387719082678, 44291128245229321])),
    Fr::new(BigInteger::new([9595762994042753249, 17961003348867830043, 14913335433940385954, 731761561225301731])),
    Fr::new(BigInteger::new([5367703213195916999, 10545246038000798248, 4539481636153953366, 3259506123418404861])),
    Fr::new(BigInteger::new([17021623008194002715, 2865048983684371552, 5056682332398940246, 1349617477692544641])),
    Fr::new(BigInteger::new([1134717827856894215, 13482002260626778920, 989565252679141365, 619861120912803244])),
    Fr::new(BigInteger::new([3341516608155143549, 12785315151325612410, 4720209788805058044, 2601972966877438725])),
    Fr::new(BigInteger::new([6063932879366023326, 16943195560973387540, 7919205620912258460, 675148156950755242])),
    Fr::new(BigInteger::new([10047929493631565474, 314978883301113313, 16803082582625196617, 3269242266838621504])),
    Fr::new(BigInteger::new([1654441829011652376, 9468150996103888145, 16599704106619754307, 1444093999360629526])),
    Fr::new(BigInteger::new([13999347372153539309, 7263691051468770135, 13325711928020024948, 608811681096503911])),
    Fr::new(BigInteger::new([6849942457919118200, 15320897128332437453, 17468740858507922350, 1428260053822055312])),
    Fr::new(BigInteger::new([6931306244367914362, 4470477457534461503, 18038260972161041955, 102441854858098332])),
    Fr::new(BigInteger::new([1502054439602418301, 17214570261609349512, 8151450776337523631, 2571727544393664300])),
    Fr::new(BigInteger::new([4937260365462278069, 12608070461069329134, 14975117670941564784, 2193498592101738452])),
    Fr::new(BigInteger::new([5592190488111184429, 10125996362218133191, 8099323106378296655, 2895913892441311695])),
    Fr::new(BigInteger::new([6633878652383874033, 5562040477655650588, 14234014603015296991, 771684144652558502])),
    Fr::new(BigInteger::new([4201756122003335425, 2282484529868000069, 11646896620616386696, 1767668688487636396])),
    Fr::new(BigInteger::new([126246710826445864, 14485907711698561534, 14016602244872929702, 2589674037285988382])),
    Fr::new(BigInteger::new([2831538134104751947, 2333577837414834874, 7514226906107426034, 1626463881750900280])),
    Fr::new(BigInteger::new([1708850883523827737, 11770994677538105544, 2350803341595058379, 1277231652917122537])),
    Fr::new(BigInteger::new([16227209767725449021, 7783189805284429681, 11059319183343319670, 3192261659499561199])),
    Fr::new(BigInteger::new([12643816306813469434, 6346477684523429997, 2248716134233048191, 2540710086286368868])),
    Fr::new(BigInteger::new([15638149125927319792, 7031477862575649323, 13753802506191120492, 3118012365487110850])),
    Fr::new(BigInteger::new([3075014646603077692, 16698815993343015975, 14448921340878426578, 1969336500142809398])),
    Fr::new(BigInteger::new([8872535911941453698, 15495913447329313995, 11309015019195627890, 3346320703876488471])),
    Fr::new(BigInteger::new([4659833022930607901, 15682818563681008470, 1197071713829293047, 557940247594550442])),
    Fr::new(BigInteger::new([18060137170346311027, 11595607637270146025, 17621085687633989742, 1601644541486744960])),
    Fr::new(BigInteger::new([13276649360751748554, 10216645227575921413, 11785815338447204136, 2508391087423247612])),
    Fr::new(BigInteger::new([5766087615970118207, 15596757462686843637, 16356902644890805396, 17699652370946781])),
    Fr::new(BigInteger::new([16551270991687032961, 11275794361545235020, 3942137710453921878, 463922749562426677])),
    Fr::new(BigInteger::new([12360461023365227252, 10175180467105396229, 13725484529147918296, 1782404668348722915])),
    Fr::new(BigInteger::new([4476748543091069074, 12855372142416245390, 14612312927154154588, 1406541024502738018])),
    Fr::new(BigInteger::new([3152583353649647196, 18289945437266080301, 11935760467914324486, 1751085858619349459])),
    Fr::new(BigInteger::new([15339605165365148650, 18367099494717994159, 13797797002919631075, 1318669205888032137])),
    Fr::new(BigInteger::new([14349550279039839426, 12128685778486076487, 1502883153707645564, 1330273237243384951])),
    Fr::new(BigInteger::new([13894463877115168909, 15632278513948197685, 12129280464243907680, 2901449794777398617])),
    Fr::new(BigInteger::new([5015711372278299976, 2426932929771703990, 6751714022795993332, 594883783400116795])),
    Fr::new(BigInteger::new([6343574817724332965, 11101789570381922581, 8761576890483033698, 3405652079475200860])),
    Fr::new(BigInteger::new([6038698508624704716, 8383730792435202017, 8791151533829099734, 1440683080910946625])),
    Fr::new(BigInteger::new([14143257735245580940, 403730304114399861, 9312562166751525616, 1068764062533244910])),
];

pub const MDS_MATRIX: &[&[Fr]] = &[
    &[
        Fr::new(BigInteger::new([14359397154288353683, 7568855942418732343, 6575810714121073298, 1603235339818113405])),
        Fr::new(BigInteger::new([108602273466007515, 16249964682517188766, 14716043256467990562, 2400229853407491193])),
        Fr::new(BigInteger::new([6353895381692353302, 4091743744793837442, 9077326780205011538, 34544310704927253])),
        Fr::new(BigInteger::new([11312809233593050308, 3529573911206627621, 7956373469564173497, 1979278223697134082])),
    ],
    &[
        Fr::new(BigInteger::new([14467917761785273344, 13691650013372381733, 16710733772935941799, 30933331812013214])),
        Fr::new(BigInteger::new([4862920257782450814, 3226053952613652889, 1631153030930653167, 1442773447642652670])),
        Fr::new(BigInteger::new([9295621759099625059, 5691074610304098547, 15519981315894646394, 1805966540740592018])),
        Fr::new(BigInteger::new([7149834460905864608, 18396687107781941015, 14544169561284541756, 2050595064587984231])),
    ],
    &[
        Fr::new(BigInteger::new([13511918451404512991, 11693407379192458206, 1210934872435280544, 1012602124237660672])),
        Fr::new(BigInteger::new([8370579706176240098, 2747575895192326834, 7476752927725609723, 1873900219658693905])),
        Fr::new(BigInteger::new([229371995065088227, 10773137276463677621, 12714674672408461909, 3455435845664866576])),
        Fr::new(BigInteger::new([17260555154749277858, 12655030879130418755, 14277566629856478313, 2956230555600691855])),
    ],
    &[
        Fr::new(BigInteger::new([4023832590491479321, 7849041908784095335, 7565170275386684359, 844576400700517462])),
        Fr::new(BigInteger::new([7004774202290679443, 8039918781331262335, 5749090311247325586, 539656596697807696])),
        Fr::new(BigInteger::new([12320988475828513141, 18271494081361904966, 8691520997971179324, 6932398130607138])),
        Fr::new(BigInteger::new([15197494995910796725, 5720252324164162974, 12162676907437121590, 266386469213347190])),
    ],
];
