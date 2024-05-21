import hashlib
import hmac
import os
import struct
import unicodedata
import bisect
import collections
import itertools
import binascii

from pywallet.addresses import EncodeBase58Check, DecodeBase58Check, b58encode, hash_160
from pywallet.conversions import ordsix, bytes_to_str
from pywallet.ecdsa import _r
from pywallet.wallet_dat_reader import Xpriv, keyinfo


bip39_wordlist = """
 abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air
 airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april
 arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome
 awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind
 biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone bonus book boost border boring borrow boss bottom bounce box boy bracket brain brand brass brave bread breeze brick bridge brief bright bring brisk
 broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canoe canvas canyon capable capital
 captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair chalk champion change chaos chapter charge chase chat cheap check cheese chef cherry chest chicken
 chief child chimney choice choose chronic chuckle chunk churn cigar cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil coin collect
 color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit
 creek crew cricket crime crisp critic crop cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide
 decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity
 dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry
 duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology economy edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact
 end endless endorse enemy energy enforce engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry envelope episode equal equip era erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite
 exclude excuse execute exercise exhaust exhibit exile exist exit exotic expand expect expire explain expose express extend extra eye eyebrow fabric face faculty fade faint faith fall false fame family famous fan fancy fantasy farm fashion fat fatal father fatigue fault favorite feature february
 federal fee feed feel female fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold follow
 food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage garden garlic garment gas gasp gate gather gauge
 gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief
 grit grocery group grow grunt guard guess guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday
 hollow home honey hood hope horn horror horse hospital host hotel hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon idea identify idle ignore ill illegal illness image imitate immense immune impact impose improve impulse inch include income
 increase index indicate indoor industry infant inflict inform inhale inherit initial inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jeans jelly
 jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kidney kind kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab label labor ladder lady lake lamp language laptop large later latin laugh laundry lava law lawn lawsuit
 layer lazy leader leaf learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely int loop lottery loud lounge
 love loyal lucky luggage lumber lunar lunch luxury lyrics machine mad magic magnet maid mail main major make mammal man manage mandate mango mansion manual maple marble march margin marine market marriage mask mass master match material math matrix matter maximum maze meadow mean measure meat
 mechanic medal media melody melt member memory mention menu mercy merge merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle mirror misery miss mistake mix mixed mixture mobile model modify mom moment monitor monkey monster month moon moral
 more morning mosquito mother motion motor mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery myth naive name napkin narrow nasty nation nature near neck need negative neglect neither nephew nerve nest net network neutral never news next nice
 night noble noise nominee noodle normal north nose notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure observe obtain obvious occur ocean october odor off offer office often oil okay old olive olympic omit once one onion online only open opera opinion
 oppose option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outer output outside oval oven over own owner oxygen oyster ozone pact paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patient patrol
 pattern pause pave payment peace peanut pear peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge
 poem poet point polar pole police pond pony pool popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote
 proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil puppy purchase purity purpose purse push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rail rain raise rally ramp ranch random range
 rapid rare rate rather raven raw razor ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue
 resemble resist resource response result retire retreat return reunion reveal review reward rhythm rib ribbon rice rich ride ridge rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie room rose rotate rough round route royal rubber rude rug
 rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security
 seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling sick side siege sight sign silent silk
 silly silver similar simple since sing siren sister situate six size skate sketch ski skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid
 solution solve someone song soon sorry sort soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon sport spot spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp
 stand start state stay steak steel stem step stereo stick still sting stock stomach stone stool story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure
 surface surge surprise surround survey suspect sustain swallow swamp swap swarm swear sweet swift swim swing switch sword symbol symptom syrup system table tackle tag tail talent talk tank tape target task taste tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme
 then theory there they thing this thought three thrive throw thumb thunder ticket tide tiger tilt timber time tiny tip tired tissue title toast tobacco today toddler toe together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist
 toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck true truly trumpet trust truth try tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
 ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique unit universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban urge usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various
 vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior
 wash wasp waste water wave way wealth weapon wear weasel weather web wedding weekend weird welcome west wet whale what wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word work world
 worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo
""".split()

PBKDF2_ROUNDS = 2048


def binary_search(a, x, lo, hi):
    hi = hi if hi is not None else len(a)
    pos = bisect.bisect_left(a, x, lo, hi)
    return pos if pos != hi and a[pos] == x else -1


class Mnemonic(object):
    def __init__(self):
        self.language = "english"
        self.radix = 2048
        self.wordlist = bip39_wordlist
        if len(self.wordlist) != self.radix:
            raise ValueError(
                "Wordlist should contain {} words, but it's {} words int instead.".format(
                    self.radix, len(self.wordlist)
                )
            )

    @staticmethod
    def normalize_string(txt):
        if isinstance(txt, bytes):
            utxt = txt.decode("utf-8")
        elif isinstance(txt, str):
            utxt = txt
        else:
            raise TypeError("String value expected")
        return unicodedata.normalize("NFKD", utxt)

    def generate(self, strength=128):
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError(
                "Invalid strength value. Allowed values are [128, 160, 192, 224, 256]."
            )
        return self.to_mnemonic(os.urandom(strength // 8))

    def to_entropy(self, words):
        if not isinstance(words, list):
            words = words.split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                "Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d)."
                % len(words)
            )
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        wordindex = 0
        if self.language == "english":
            use_binary_search = True
        else:
            use_binary_search = False
        for word in words:
            ndx = (
                binary_search(self.wordlist, word)
                if use_binary_search
                else self.wordlist.index(word)
            )
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            for ii in range(11):
                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            wordindex += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        entropy = bytearray(entropyLengthBits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        hashBytes = hashlib.sha256(entropy).digest()
        hashBits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes
            )
        )
        for i in range(checksumLengthBits):
            if concatBits[entropyLengthBits + i] != hashBits[i]:
                raise ValueError("Failed checksum.")
        return entropy

    def to_mnemonic(self, data):
        if len(data) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                "Data length should be one of the following: [16, 20, 24, 28, 32], but is {}.".format(
                    len(data)
                )
            )
        h = hashlib.sha256(data).hexdigest()
        b = (
            bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
            + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
        )
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11 : (i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        if self.language == "japanese":
            result_phrase = "\u3000".join(result)
        else:
            result_phrase = " ".join(result)
        return result_phrase

    def check(self, mnemonic):
        mnemonic_list = self.normalize_string(mnemonic).split(" ")
        if len(mnemonic_list) not in [12, 15, 18, 21, 24]:
            return False
        try:
            idx = map(lambda x: bin(self.wordlist.index(x))[2:].zfill(11), mnemonic_list)
            b = "".join(idx)
        except ValueError:
            return False
        l = len(b)  # noqa: E741
        d = b[: l // 33 * 32]
        h = b[-l // 33 :]
        nd = int(d, 2).to_bytes(l // 33 * 4, byteorder="big")
        nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[: l // 33]
        return h == nh

    def expand_word(self, prefix):
        if prefix in self.wordlist:
            return prefix
        else:
            matches = [word for word in self.wordlist if word.startswith(prefix)]
            if len(matches) == 1:  # matched exactly one word in the wordlist
                return matches[0]
            else:
                return prefix

    def expand(self, mnemonic):
        return " ".join(map(self.expand_word, mnemonic.split(" ")))

    @classmethod
    def to_seed(cls, mnemonic, passphrase=""):
        mnemonic = cls.normalize_string(mnemonic)
        passphrase = cls.normalize_string(passphrase)
        passphrase = "mnemonic" + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        stretched = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS)
        return stretched[:64]

    @classmethod
    def mnemonic_to_xprv(cls, mnemonic, passphrase=""):
        seed = cls.to_seed(mnemonic, passphrase)
        return Xpriv.from_seed(seed)

    @staticmethod
    def to_hd_master_key(seed, testnet=False):
        if len(seed) != 64:
            raise ValueError("Provided seed should have length of 64")
        seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()
        xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet
        if testnet:
            xprv = b"\x04\x35\x83\x94"  # Version for private testnet
        xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
        xprv += seed[32:]  # Chain code
        xprv += b"\x00" + seed[:32]  # Master key
        hashed_xprv = hashlib.sha256(xprv).digest()
        hashed_xprv = hashlib.sha256(hashed_xprv).digest()
        xprv += hashed_xprv[:4]
        return b58encode(xprv)


def parse_ckd_path(str_path):
    str_path = str_path.lstrip("m/")
    path_split = []
    for j in str_path.split("/"):
        if not j:
            continue
        hardened = 0
        if j.endswith("'") or j.lower().endswith("h"):
            hardened = 0x80000000
            j = j[:-1]
        try:
            path_split.append([int(j) + hardened])
        except:
            a, b = map(int, j.split("-"))
            path_split.append(list(range(a + hardened, b + 1 + hardened)))
    return path_split


class Xpriv(collections.namedtuple("XprivNT", "version depth prt_fpr childnr cc ktype key")):
    xpriv_fmt = ">IB4sI32sB32s"

    def __new__(cls, *a, **kw):
        self = super(Xpriv, cls).__new__(cls, *a, **kw)
        self.fullpath = "m"
        return self

    @classmethod
    def xpriv_version_bytes(cls):
        return 0x0488ADE4

    @classmethod
    def xpub_version_bytes(cls):
        return 0x0488B21E

    @classmethod
    def from_mnemomic(cls, mnemonic, passphrase=""):
        return Mnemonic().mnemonic_to_xprv(mnemonic, passphrase)

    @classmethod
    def from_seed(cls, s, seed=b"Bitcoin seed"):
        I = hmac.new(seed, s, digestmod=hashlib.sha512).digest()
        mk, cc = I[:32], I[32:]
        return cls(cls.xpriv_version_bytes(), 0, b"\x00" * 4, 0, cc, 0, mk)

    def clone(self):
        return self.__class__.b58decode(self.b58encode())

    def b58encode(self):
        return EncodeBase58Check(struct.pack(self.xpriv_fmt, *self._asdict().values()))

    def address(self, **kw):
        return keyinfo(self, kw.get("network"), False, True).addr

    def key_hex(self):
        return binascii.hexlify(self.key)

    def xpub(self, **kw):
        pubk = keyinfo(self, None, False, True).public_key
        xpub_content = self.clone()._replace(
            version=self.xpub_version_bytes(), ktype=ordsix(pubk[0]), key=pubk[1:]
        )
        return EncodeBase58Check(struct.pack(self.xpriv_fmt, *xpub_content))

    @classmethod
    def b58decode(cls, b58xpriv):
        return cls(*struct.unpack(cls.xpriv_fmt, DecodeBase58Check(b58xpriv)))

    def multi_ckd_xpriv(self, str_path):
        path_split = parse_ckd_path(str_path)
        rev_path_split = path_split[::-1]
        xprivs = [self]
        while rev_path_split:
            children_nrs = rev_path_split.pop()
            xprivs = [parent.ckd_xpriv(child_nr) for parent in xprivs for child_nr in children_nrs]
        return xprivs

    def set_fullpath(self, base, x):
        self.fullpath = base + "/" + ("%d'" % (x - 0x80000000) if x >= 0x80000000 else "%d" % x)
        return self

    def ckd_xpriv(self, *indexes):
        if indexes.__class__ != tuple:
            indexes = [indexes]
        if indexes[0].__class__ != int:
            indexes = list(map(lambda x: x[0], parse_ckd_path(indexes[0])))
        i = indexes[0]
        if i < 0:
            i = 0x80000000 - i
        assert self.ktype == 0
        par_pubk = keyinfo(self, None, False, True).public_key
        seri = struct.pack(">I", i)
        if i >= 0x80000000:
            I = hmac.new(self.cc, b"\x00" + self.key + seri, digestmod=hashlib.sha512).digest()
        else:
            I = hmac.new(self.cc, par_pubk + seri, digestmod=hashlib.sha512).digest()
        il, ir = I[:32], I[32:]
        pk = (
            hex((int(binascii.hexlify(il), 16) + int(binascii.hexlify(self.key), 16)) % _r)[2:]
            .replace("L", "")
            .zfill(64)
        )
        child = self.__class__(
            self.version,
            self.depth + 1,
            hash_160(par_pubk)[:4],
            i,
            ir,
            0,
            binascii.unhexlify(pk),
        ).set_fullpath(self.fullpath, i)
        if len(indexes) >= 2:
            return child.ckd_xpriv(*indexes[1:])
        return child

    def hprivcontent(self):
        return binascii.hexlify(DecodeBase58Check(self.b58encode()))

    def hpubcontent(self):
        return binascii.hexlify(DecodeBase58Check(self.xpub()))

    def keyinfo(self, network_name="Bitcoin"):
        keyinfo(self, network_name, True, False)
        print()
        keyinfo(self, network_name, True, True)


def dump_bip32_privkeys(xpriv, paths="m/0", fmt="addr", **kw):
    if fmt == "addr":
        dump_key = lambda x: x.addr
    elif fmt == "privkey":
        dump_key = lambda x: bytes_to_str(binascii.hexlify(x.secret))
    elif fmt == "addrprivkey":
        dump_key = lambda x: x.addr + " " + bytes_to_str(binascii.hexlify(x.secret))
    elif fmt == "addrwif":
        dump_key = lambda x: x.addr + " " + x.wif
    else:
        dump_key = lambda x: x.wif
    try:
        xpriv = Xpriv.b58decode(xpriv)
    except:
        pass
    for child in xpriv.multi_ckd_xpriv(paths):
        print(
            "%s: %s" % (child.fullpath, dump_key(keyinfo(child, kw.get("network"), False, True)))
        )
