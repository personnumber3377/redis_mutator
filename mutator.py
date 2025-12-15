#!/usr/bin/env python3
"""
AFL++ Python custom mutator for Redis command-sequence inputs.

- Supports ALL commands listed in cmds.txt (from server.c command table).
- Generates structured commands using lightweight specs (arity + arg "kinds"),
  then performs structure-aware mutations (arg count, list explosion, etc).
- Deterministic RNG derived from input bytes.

Input format (default): inline CLI-like lines:
  SET key value
  HSET hash field value
  XACKDEL stream group IDS 56 id1 id2 ...

Output format:
  MUTATOR_REDIS_FORMAT=inline (default)
  MUTATOR_REDIS_FORMAT=resp   (strict RESP arrays)

Environment:
  MUTATOR_REDIS_COUNT : fuzz_count() return value (default 64)
  MUTATOR_REDIS_FORMAT: inline|resp
  MUTATOR_REDIS_MAX_CMDS: cap program length (default 2000)
  MUTATOR_REDIS_MAX_ARGS: cap args per command (default 4096)
"""

from __future__ import annotations
import os
import re
import hashlib
import random
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

# -------------------------
# AFL++ knobs
# -------------------------
DEFAULT_MUTATION_COUNT = int(os.environ.get("MUTATOR_REDIS_COUNT", "64"))
FMT = os.environ.get("MUTATOR_REDIS_FORMAT", "inline").strip().lower()  # inline|resp
MAX_CMDS = int(os.environ.get("MUTATOR_REDIS_MAX_CMDS", "2000"))
MAX_ARGS = int(os.environ.get("MUTATOR_REDIS_MAX_ARGS", "4096"))

_initialized = False
_mutation_count = DEFAULT_MUTATION_COUNT

# -------------------------
# Tokenization (inline)
# -------------------------
_TOKEN_RE = re.compile(
    r'''
    " (?: \\ . | [^"\\] )* "     |   # "..."
    [^\s]+                          # bare
    ''',
    re.VERBOSE
)

def _unquote(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        inner = tok[1:-1]
        inner = inner.replace(r'\"', '"').replace(r'\\', '\\')
        return inner
    return tok

def _quote(tok: str, rng: random.Random) -> str:
    if tok is None:
        tok = ""
    if any(c.isspace() for c in tok) or '"' in tok or rng.random() < 0.10:
        escaped = tok.replace('\\', r'\\').replace('"', r'\"')
        return f'"{escaped}"'
    return tok

def parse_inline(buf: bytes) -> List[List[str]]:
    try:
        s = buf.decode("utf-8", errors="replace")
    except Exception:
        s = buf.decode("latin1", errors="replace")

    out: List[List[str]] = []
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("//"):
            continue
        toks = _TOKEN_RE.findall(line)
        if not toks:
            continue
        argv = [_unquote(t) for t in toks]
        out.append(argv)
    return out

def render_inline(cmds: List[List[str]], rng: random.Random) -> bytes:
    lines: List[str] = []
    for argv in cmds:
        if not argv:
            continue
        rendered = " ".join(_quote(a, rng) for a in argv)
        lines.append(rendered)
    return ("\n".join(lines) + "\n").encode("utf-8", errors="ignore")

def render_resp(cmds: List[List[str]]) -> bytes:
    """
    Strict RESP arrays:
      *<argc>\r\n
      $<len>\r\n<payload>\r\n
    """
    out = bytearray()
    for argv in cmds:
        if not argv:
            continue
        out += f"*{len(argv)}\r\n".encode("ascii", errors="ignore")
        for a in argv:
            if a is None:
                a = ""
            b = a.encode("utf-8", errors="ignore")
            out += f"${len(b)}\r\n".encode("ascii", errors="ignore")
            out += b + b"\r\n"
            # NOTE: intentionally non-strict payload duplication is *removed* by default in this version.
            # If you want strict RESP, replace `b + b` with `b`.
            # Keeping it as-is here can tickle parser oddities.
    return bytes(out)

# If you want strict RESP (recommended for server protocol fuzzing), flip this:
STRICT_RESP = bool(int(os.environ.get("MUTATOR_REDIS_STRICT_RESP", "1")))
def render_resp_strict(cmds: List[List[str]]) -> bytes:
    out = bytearray()
    for argv in cmds:
        if not argv:
            continue
        out += f"*{len(argv)}\r\n".encode("ascii", errors="ignore")
        for a in argv:
            if a is None:
                a = ""
            b = a.encode("utf-8", errors="ignore")
            out += f"${len(b)}\r\n".encode("ascii", errors="ignore")
            out += b + b"\r\n" if not STRICT_RESP else b + b"\r\n"  # keep toggle
    return bytes(out)

# -------------------------
# Deterministic RNG
# -------------------------
def rng_from_buf(buf: bytes) -> random.Random:
    h = hashlib.sha256(buf[:256]).digest()
    seed = int.from_bytes(h[:8], "little", signed=False)
    return random.Random(seed)

# -------------------------
# Dictionaries / atoms
# -------------------------

REDIS_OPTIONS = [
    # ---- Common modifiers / toggles ----
    "NX","XX","CH","INCR","GT","LT",
    "WITHSCORES","LIMIT","COUNT","BLOCK",
    "ASC","DESC","ALPHA",
    "STORE","STOREDIST",
    "BY","GET",
    "MATCH","TYPE",
    "WEIGHTS","AGGREGATE","SUM","MIN","MAX",
    "REV","BYLEX","BYSCORE",

    # ---- Streams ----
    "MKSTREAM","NOMKSTREAM",
    "JUSTID","NOACK","FORCE",
    "IDLE","TIME","RETRYCOUNT","LASTID",
    "ENTRIESADDED","ENTRIESREAD",
    "GROUP","GROUPS","CONSUMERS","STREAM","STREAMS",

    # ---- XGROUP subcommands ----
    "CREATE","CREATECONSUMER","DELCONSUMER",
    "DESTROY","SETID",

    # ---- PubSub ----
    "CHANNELS","NUMSUB","NUMPAT",
    "SHARDCHANNELS","SHARDNUMSUB",

    # ---- ACL ----
    "ON","OFF",
    "ALLKEYS","RESETKEYS","~*",
    "ALLCHANNELS","RESETCHANNELS","&*",
    "ALLCOMMANDS","+@ALL",
    "NOCOMMANDS","-@ALL",
    "NOPASS","RESETPASS",
    "SETUSER","DELUSER","GETUSER",
    "LIST","USERS","WHOAMI",
    "LOAD","SAVE","CAT","GENPASS","LOG",

    # ---- CLIENT ----
    "KILL","LIST","ID","TYPE","ADDR","LADDR",
    "USER","SKIPME","YES","NO",
    "REPLY","ON","OFF","SKIP",
    "PAUSE","UNPAUSE","WRITE","ALL",
    "TRACKING","REDIRECT","BCAST","OPTIN","OPTOUT","NOLOOP","PREFIX",
    "CACHING","GETREDIR","TRACKINGINFO",

    # ---- CONFIG ----
    "GET","SET","RESETSTAT","REWRITE",
    "BIND","DIR","LOGFILE","INCLUDE",
    "SAVE","NOSAVE",
    "RENAME-COMMAND",
    "CLIENT-OUTPUT-BUFFER-LIMIT",
    "OOM-SCORE-ADJ-VALUES",
    "NOTIFY-KEYSPACE-EVENTS",
    "LOADMODULE",
    "SENTINEL",

    # ---- DEBUG ----
    "SEGFAULT","PANIC","OOM","ASSERT",
    "RESTART","CRASH-AND-RECOVER",
    "LOG","LEAK","RELOAD",
    "MERGE","NOFLUSH","NOSAVE",
    "OBJECT","SDSLEN","ZIPLIST",
    "POPULATE","DIGEST","DIGEST-VALUE",
    "PROTOCOL","STRING","INTEGER","DOUBLE","BIGNUM",
    "NULL","ARRAY","SET","MAP","ATTRIB","PUSH",
    "TRUE","FALSE","VERBATIM",
    "SLEEP","ERROR","STRUCTSIZE",
    "HTSTATS","HTSTATS-KEY",
    "CHANGE-REPL-ID",

    # ---- CLUSTER ----
    "MEET","NODES","MYID","SLOTS",
    "FLUSHSLOTS","ADDSLOTS","DELSLOTS",
    "SETSLOT","MIGRATING","IMPORTING","STABLE","NODE",
    "BUMPEPOCH","INFO","SAVECONFIG",
    "KEYSLOT","COUNTKEYSINSLOT","GETKEYSINSLOT",
    "FORGET","REPLICATE",
    "SLAVES","REPLICAS",
    "COUNT-FAILURE-REPORTS",
    "FAILOVER","TAKEOVER","FORCE",
    "SET-CONFIG-EPOCH",
    "RESET","HARD","SOFT",

    # ---- GEO ----
    "WITHDIST","WITHHASH","WITHCOORD",
    "ANY","FROMMEMBER","FROMLONLAT",
    "BYRADIUS","BYBOX",

    # ---- SORT ----
    "ASC","DESC","ALPHA","LIMIT","STORE","BY","GET",

    # ---- SCRIPT / LUA ----
    "FLUSH","SYNC","ASYNC","EXISTS","KILL",
    "DEBUG","YES","NO",
    "HELP","STEP","NEXT","CONTINUE","TRACE",
    "MAXLEN","BREAK","EVAL","ABORT","REDIS",
    "PRINT","LIST","WHOLE",

    # ---- REPLICATION / PSYNC ----
    "ACK","GETACK","CAPA","EOF","PSYNC2",
    "RDB-ONLY","LISTENING-PORT","IP-ADDRESS",
    "TIMEOUT","TO",

    # ---- MEMORY / OBJECT ----
    "REFCOUNT","ENCODING","IDLETIME","FREQ",
    "USAGE","SAMPLES","STATS","MALLOC-STATS","DOCTOR","PURGE",

    # ---- Sentinel ----
    "MONITOR","DOWN-AFTER-MILLISECONDS","FAILOVER-TIMEOUT",
    "PARALLEL-SYNCS","NOTIFICATION-SCRIPT","CLIENT-RECONFIG-SCRIPT",
    "AUTH-PASS","AUTH-USER","QUORUM",
    "CURRENT-EPOCH","LEADER-EPOCH",
    "KNOWN-SLAVE","KNOWN-REPLICA","KNOWN-SENTINEL",
    "ANNOUNCE-IP","ANNOUNCE-PORT",
    "DENY-SCRIPTS-RECONFIG",
    "SENTINEL-USER","SENTINEL-PASS",
    "RESOLVE-HOSTNAMES","ANNOUNCE-HOSTNAMES",
    "MASTERS","MASTER","SENTINELS",
    "IS-MASTER-DOWN-BY-ADDR",
    "PENDING-SCRIPTS","FLUSHCONFIG",
    "REMOVE","CKQUORUM","SIMULATE-FAILURE",
    "CRASH-AFTER-ELECTION","CRASH-AFTER-PROMOTION",

    # ---- Units / misc ----
    "B","K","KB","M","MB","G","GB",
]

TOKENS = [
    "", "0", "1", "-1", "2", "7", "8", "9", "15", "16", "31", "32", "63", "64",
    "127", "128", "255", "256", "511", "512", "1023", "1024", "4096", "65535",
    "2147483647", "-2147483648", "9223372036854775807", "-9223372036854775808",
    "NaN", "Inf", "-Inf", "1e309", "-1e309",
    "A", "AA", "AAAA", "B"*64, "C"*256,
    "hello", "world", "fuzz", "FUZZ", "😈",
    "key", "k", "mykey", "dolly", "clone", "zz", "myhash",
    "field", "field1", "field2", "value", "value1", "value2", "QQQQQQQQ",
    "IDS", "COUNT", "BLOCK", "MKSTREAM", "JUSTID", "NOMKSTREAM",
    "OK", "ERR", "nil", "null",
] + REDIS_OPTIONS # Also add the option stuff here...

KEYS = [
    "k", "k1", "k2", "key", "mykey", "dolly", "clone", "zz", "myhash",
    "list", "set", "zset",
    "stream", "mystream", "3418133648", "3779513606",
]

FIELDS = ["f", "f1", "f2", "aa", "bb", "field", "field1", "field2"]
VALUES = ["v", "v1", "v2", "1337", "Hello", "World", "HelloWorld", "99", "-256", "sheep"]
GROUPS = ["g", "mygroup", "group", "3779513606"]
CONSUMERS = ["c", "myconsumer", "consumer"]

def gen_stream_id(rng: random.Random) -> str:
    ms = rng.randrange(0, 2**48)
    seq = rng.randrange(0, 2**16)
    return f"{ms}-{seq}"

def gen_float(rng: random.Random) -> str:
    if rng.random() < 0.2:
        return random.choice(["NaN", "Inf", "-Inf", "1e309", "-1e309"])
    # typical / extreme
    v = (rng.random() - 0.5) * (10 ** rng.randrange(0, 12))
    return str(v)

def gen_int(rng: random.Random) -> str:
    if rng.random() < 0.3:
        return random.choice([
            "-1","0","1","7","8","9","15","16","31","32","63","64",
            "127","128","255","256","1024","4096",
            "2147483647","-2147483648","9223372036854775807","-9223372036854775808"
        ])
    return str(rng.randrange(-2**31, 2**31))

def gen_key(rng: random.Random) -> str:
    if rng.random() < 0.7:
        return random.choice(KEYS)
    return mutate_string(random.choice(KEYS), rng)

def gen_field(rng: random.Random) -> str:
    return random.choice(FIELDS) if rng.random() < 0.8 else mutate_string(random.choice(FIELDS), rng)

def gen_value(rng: random.Random) -> str:
    return random.choice(VALUES) if rng.random() < 0.8 else mutate_string(random.choice(VALUES), rng)

def gen_pattern(rng: random.Random) -> str:
    return random.choice(["*", "k*", "user:*", "zz*", "stream*", "??", "[a-z]*", "\\x00*", ".*"])

def gen_channel(rng: random.Random) -> str:
    return random.choice(["chan", "news", "updates", "pub", "sub", "x", "test"])

# -------------------------
# Command universe (from your cmds.txt)
# -------------------------
ALL_COMMANDS = [
    "acl","append","asking","auth","bgrewriteaof","bgsave","bitcount","bitfield","bitfield_ro",
    "bitop","bitpos","blmove","blpop","brpop","brpoplpush","bzpopmax","bzpopmin","client",
    "cluster","command","config","copy","dbsize","debug","decr","decrby","del","discard","dump",
    "echo","eval","evalsha","exec","exists","expire","expireat","failover","flushall","flushdb",
    "geoadd","geodist","geohash","geopos","georadius","georadiusbymember","georadiusbymember_ro",
    "georadius_ro","geosearch","geosearchstore","get","getbit","getdel","getex","getrange","getset",
    "hdel","hello","hexists","hget","hgetall","hincrby","hincrbyfloat","hkeys","hlen","hmget","hmset",
    "host:","hrandfield","hscan","hset","hsetnx","hstrlen","hvals","incr","incrby","incrbyfloat",
    "info","keys","lastsave","latency","lindex","linsert","llen","lmove","lolwut","lpop","lpos",
    "lpush","lpushx","lrange","lrem","lset","ltrim","memory","mget","migrate","module","monitor",
    "move","mset","msetnx","multi","object","persist","pexpire","pexpireat","pfadd","pfcount",
    "pfdebug","pfmerge","pfselftest","ping","post","psetex","psubscribe","psync","pttl","publish",
    "pubsub","punsubscribe","randomkey","readonly","readwrite","rename","renamenx","replconf",
    "replicaof","reset","restore","restore-asking","role","rpop","rpoplpush","rpush","rpushx","sadd",
    "save","scan","scard","script","sdiff","sdiffstore","select","set","setbit","setex","setnx",
    "setrange","shutdown","sinter","sinterstore","sismember","slaveof","slowlog","smembers",
    "smismember","smove","sort","spop","srandmember","srem","sscan","stralgo","strlen","subscribe",
    "substr","sunion","sunionstore","swapdb","sync","time","touch","ttl","type","unlink","unsubscribe",
    "unwatch","wait","watch","xack","xadd","xautoclaim","xclaim","xdel","xgroup","xinfo","xlen",
    "xpending","xrange","xread","xreadgroup","xrevrange","xsetid","xtrim","zadd","zcard","zcount",
    "zdiff","zdiffstore","zincrby","zinter","zinterstore","zlexcount","zmscore","zpopmax","zpopmin",
    "zrandmember","zrange","zrangebylex","zrangebyscore","zrangestore","zrank","zrem","zremrangebylex",
    "zremrangebyrank","zremrangebyscore","zrevrange","zrevrangebylex","zrevrangebyscore","zrevrank",
    "zscan","zscore","zunion","zunionstore"
]

ALL_COMMANDS_UP = [c.upper() for c in ALL_COMMANDS]

# -------------------------
# Spec-driven generation
# -------------------------

@dataclass
class Spec:
    # min args excluding command, and a generator for argv (including cmd)
    gen: Callable[[random.Random], List[str]]

def cmd(*parts: str) -> List[str]:
    return [p for p in parts]

def gen_kv_pair_list(rng: random.Random, n_pairs: int) -> List[str]:
    out: List[str] = []
    for _ in range(n_pairs):
        out.append(gen_key(rng))
        out.append(gen_value(rng))
    return out

def gen_field_value_list(rng: random.Random, n_pairs: int) -> List[str]:
    out: List[str] = []
    for _ in range(n_pairs):
        out.append(gen_field(rng))
        out.append(gen_value(rng))
    return out

def gen_members(rng: random.Random, n: int) -> List[str]:
    return [gen_value(rng) for _ in range(n)]

def gen_stream_ids(rng: random.Random, n: int) -> List[str]:
    ids = []
    for _ in range(n):
        ids.append(gen_stream_id(rng) if rng.random() < 0.85 else mutate_string(gen_stream_id(rng), rng))
    return ids

def gen_zadd_pairs(rng: random.Random, n: int) -> List[str]:
    out: List[str] = []
    for _ in range(n):
        out.append(gen_float(rng))
        out.append(gen_value(rng))
    return out

def gen_minimal_eval(rng: random.Random) -> List[str]:
    # Keep it simple but mutate-able
    script = random.choice([
        "return 1",
        "return redis.call('PING')",
        "redis.call('SET','k','v'); return redis.call('GET','k')",
        "redis.call('XADD','mystream','*','f','v'); return 0",
    ])
    # numkeys
    numkeys = random.choice(["0","1","2"])
    argv = ["EVAL", script, numkeys]
    for _ in range(int(numkeys)):
        argv.append(gen_key(rng))
    # add some args
    if rng.random() < 0.6:
        argv += [gen_value(rng) for _ in range(rng.randrange(0, 10))]
    return argv

def gen_scan_like(rng: random.Random, base: str) -> List[str]:
    argv = [base, gen_int(rng) if base != "SCAN" else gen_int(rng)]
    if rng.random() < 0.6:
        argv += ["MATCH", gen_pattern(rng)]
    if rng.random() < 0.6:
        argv += ["COUNT", str(rng.randrange(0, 100000))]
    if rng.random() < 0.2:
        argv += ["TYPE", random.choice(["string","hash","list","set","zset","stream"])]
    return argv

def gen_xgroup(rng: random.Random) -> List[str]:
    stream = gen_key(rng)
    group = random.choice(GROUPS)
    sub = random.choice(["CREATE","CREATECONSUMER","DELCONSUMER","DESTROY","SETID"])
    if sub == "CREATE":
        return ["XGROUP","CREATE",stream,group,random.choice(["0-0","$"]),random.choice(["MKSTREAM","ENTRIESREAD","0","1","2","500"])]
    if sub == "SETID":
        return ["XGROUP","SETID",stream,group,random.choice(["0-0","$","1-0",gen_stream_id(rng)])]
    if sub == "CREATECONSUMER":
        return ["XGROUP","CREATECONSUMER",stream,group,random.choice(CONSUMERS)]
    if sub == "DELCONSUMER":
        return ["XGROUP","DELCONSUMER",stream,group,random.choice(CONSUMERS)]
    return ["XGROUP","DESTROY",stream,group]

def gen_xreadgroup(rng: random.Random) -> List[str]:
    stream = gen_key(rng)
    group = random.choice(GROUPS)
    consumer = random.choice(CONSUMERS)
    argv = ["XREADGROUP","GROUP",group,consumer]
    if rng.random() < 0.7:
        argv += ["COUNT", str(rng.randrange(0, 100000))]
    if rng.random() < 0.5:
        argv += ["BLOCK", str(rng.randrange(0, 100000))]
    argv += ["STREAMS", stream, random.choice([">","0-0",gen_stream_id(rng)])]
    return argv

def gen_xackdel_like(rng: random.Random, name: str) -> List[str]:
    stream = gen_key(rng)
    group = random.choice(GROUPS)
    # make it frequently exceed 8 (vector overflow style)
    n = rng.choice([0,1,2,7,8,9,10,15,16,17,31,32,64,65,128])
    ids = gen_stream_ids(rng, max(0, min(n + (rng.randrange(0, 128) if rng.random() < 0.3 else 0), 512)))
    argv = [name, stream, group, "IDS", str(n)] + ids
    return argv

def gen_zinter_union(rng: random.Random, name: str) -> List[str]:
    # ZINTER/ZUNION: ZINTER numkeys key [key ...] [WEIGHTS w ...] [AGGREGATE SUM|MIN|MAX] [WITHSCORES]
    numkeys = rng.randrange(0, 32)
    keys = [gen_key(rng) for _ in range(numkeys)]
    argv = [name, str(numkeys)] + keys
    if rng.random() < 0.5 and numkeys > 0:
        argv += ["WEIGHTS"] + [gen_float(rng) for _ in range(numkeys)]
    if rng.random() < 0.5:
        argv += ["AGGREGATE", random.choice(["SUM","MIN","MAX","foo",""])]
    if rng.random() < 0.3:
        argv += ["WITHSCORES"]
    return argv

# Spec table for many common commands; the rest will be handled generically
SPECS: Dict[str, Spec] = {}

def add_spec(name: str, fn: Callable[[random.Random], List[str]]):
    SPECS[name.upper()] = Spec(gen=fn)

# Core strings
add_spec("PING", lambda r: ["PING"] if r.random() < 0.5 else ["PING", gen_value(r)])
add_spec("ECHO", lambda r: ["ECHO", gen_value(r)])
add_spec("GET", lambda r: ["GET", gen_key(r)])
add_spec("SET", lambda r: ["SET", gen_key(r), gen_value(r)] + (["EX", str(r.randrange(0, 100000))] if r.random() < 0.3 else []) + (["PX", str(r.randrange(0, 100000))] if r.random() < 0.2 else []) + (["NX"] if r.random() < 0.2 else []) + (["XX"] if r.random() < 0.2 else []))
add_spec("APPEND", lambda r: ["APPEND", gen_key(r), gen_value(r)])
add_spec("INCR", lambda r: ["INCR", gen_key(r)])
add_spec("INCRBY", lambda r: ["INCRBY", gen_key(r), gen_int(r)])
add_spec("INCRBYFLOAT", lambda r: ["INCRBYFLOAT", gen_key(r), gen_float(r)])
add_spec("DECR", lambda r: ["DECR", gen_key(r)])
add_spec("DECRBY", lambda r: ["DECRBY", gen_key(r), gen_int(r)])
add_spec("STRLEN", lambda r: ["STRLEN", gen_key(r)])
add_spec("GETRANGE", lambda r: ["GETRANGE", gen_key(r), gen_int(r), gen_int(r)])
add_spec("SETRANGE", lambda r: ["SETRANGE", gen_key(r), gen_int(r), gen_value(r)])
add_spec("GETSET", lambda r: ["GETSET", gen_key(r), gen_value(r)])
add_spec("GETDEL", lambda r: ["GETDEL", gen_key(r)])
add_spec("GETEX", lambda r: ["GETEX", gen_key(r)] + random.choice([["EX", str(r.randrange(0, 100000))], ["PX", str(r.randrange(0, 100000))], ["PERSIST"], []]))
add_spec("SETEX", lambda r: ["SETEX", gen_key(r), str(r.randrange(0, 100000)), gen_value(r)])
add_spec("PSETEX", lambda r: ["PSETEX", gen_key(r), str(r.randrange(0, 100000)), gen_value(r)])
add_spec("SETNX", lambda r: ["SETNX", gen_key(r), gen_value(r)])

# Keyspace
add_spec("DEL", lambda r: ["DEL"] + [gen_key(r) for _ in range(r.randrange(0, 128))])
add_spec("UNLINK", lambda r: ["UNLINK"] + [gen_key(r) for _ in range(r.randrange(0, 128))])
add_spec("EXISTS", lambda r: ["EXISTS"] + [gen_key(r) for _ in range(r.randrange(0, 128))])
add_spec("TYPE", lambda r: ["TYPE", gen_key(r)])
add_spec("TTL", lambda r: ["TTL", gen_key(r)])
add_spec("PTTL", lambda r: ["PTTL", gen_key(r)])
add_spec("EXPIRE", lambda r: ["EXPIRE", gen_key(r), str(r.randrange(-10, 100000))])
add_spec("PEXPIRE", lambda r: ["PEXPIRE", gen_key(r), str(r.randrange(-10, 100000))])
add_spec("EXPIREAT", lambda r: ["EXPIREAT", gen_key(r), str(r.randrange(-10, 2**31))])
add_spec("PEXPIREAT", lambda r: ["PEXPIREAT", gen_key(r), str(r.randrange(-10, 2**31))])
add_spec("PERSIST", lambda r: ["PERSIST", gen_key(r)])
add_spec("RENAME", lambda r: ["RENAME", gen_key(r), gen_key(r)])
add_spec("RENAMENX", lambda r: ["RENAMENX", gen_key(r), gen_key(r)])
add_spec("MOVE", lambda r: ["MOVE", gen_key(r), str(r.randrange(-10, 100))])
add_spec("SELECT", lambda r: ["SELECT", str(r.randrange(-10, 256))])
add_spec("KEYS", lambda r: ["KEYS", gen_pattern(r)])
add_spec("DBSIZE", lambda r: ["DBSIZE"])
add_spec("RANDOMKEY", lambda r: ["RANDOMKEY"])

# Hashes
add_spec("HSET", lambda r: ["HSET", gen_key(r)] + gen_field_value_list(r, r.randrange(0, 64)))
add_spec("HSETNX", lambda r: ["HSETNX", gen_key(r), gen_field(r), gen_value(r)])
add_spec("HGET", lambda r: ["HGET", gen_key(r), gen_field(r)])
add_spec("HGETALL", lambda r: ["HGETALL", gen_key(r)])
add_spec("HDEL", lambda r: ["HDEL", gen_key(r)] + [gen_field(r) for _ in range(r.randrange(0, 128))])
add_spec("HEXISTS", lambda r: ["HEXISTS", gen_key(r), gen_field(r)])
add_spec("HLEN", lambda r: ["HLEN", gen_key(r)])
add_spec("HSTRLEN", lambda r: ["HSTRLEN", gen_key(r), gen_field(r)])
add_spec("HINCRBY", lambda r: ["HINCRBY", gen_key(r), gen_field(r), gen_int(r)])
add_spec("HINCRBYFLOAT", lambda r: ["HINCRBYFLOAT", gen_key(r), gen_field(r), gen_float(r)])
add_spec("HKEYS", lambda r: ["HKEYS", gen_key(r)])
add_spec("HVALS", lambda r: ["HVALS", gen_key(r)])
add_spec("HMGET", lambda r: ["HMGET", gen_key(r)] + [gen_field(r) for _ in range(r.randrange(0, 128))])
add_spec("HMSET", lambda r: ["HMSET", gen_key(r)] + gen_field_value_list(r, r.randrange(0, 64)))
add_spec("HRANDFIELD", lambda r: ["HRANDFIELD", gen_key(r)] + ([gen_int(r)] if r.random() < 0.7 else []) + (["WITHVALUES"] if r.random() < 0.4 else []))
add_spec("HSCAN", lambda r: ["HSCAN", gen_key(r), gen_int(r)] + (["MATCH", gen_pattern(r)] if r.random() < 0.6 else []) + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.6 else []))

# Lists
add_spec("LPUSH", lambda r: ["LPUSH", gen_key(r)] + gen_members(r, r.randrange(0, 256)))
add_spec("RPUSH", lambda r: ["RPUSH", gen_key(r)] + gen_members(r, r.randrange(0, 256)))
add_spec("LPUSHX", lambda r: ["LPUSHX", gen_key(r)] + gen_members(r, r.randrange(0, 256)))
add_spec("RPUSHX", lambda r: ["RPUSHX", gen_key(r)] + gen_members(r, r.randrange(0, 256)))
add_spec("LPOP", lambda r: ["LPOP", gen_key(r)] + ([str(r.randrange(0, 100000))] if r.random() < 0.5 else []))
add_spec("RPOP", lambda r: ["RPOP", gen_key(r)] + ([str(r.randrange(0, 100000))] if r.random() < 0.5 else []))
add_spec("LRANGE", lambda r: ["LRANGE", gen_key(r), gen_int(r), gen_int(r)])
add_spec("LLEN", lambda r: ["LLEN", gen_key(r)])
add_spec("LINDEX", lambda r: ["LINDEX", gen_key(r), gen_int(r)])
add_spec("LSET", lambda r: ["LSET", gen_key(r), gen_int(r), gen_value(r)])
add_spec("LREM", lambda r: ["LREM", gen_key(r), gen_int(r), gen_value(r)])
add_spec("LTRIM", lambda r: ["LTRIM", gen_key(r), gen_int(r), gen_int(r)])
add_spec("LINSERT", lambda r: ["LINSERT", gen_key(r), random.choice(["BEFORE","AFTER","X",""]), gen_value(r), gen_value(r)])
add_spec("RPOPLPUSH", lambda r: ["RPOPLPUSH", gen_key(r), gen_key(r)])
add_spec("LMOVE", lambda r: ["LMOVE", gen_key(r), gen_key(r), random.choice(["LEFT","RIGHT","X",""]), random.choice(["LEFT","RIGHT","Y",""])])

# Sets
add_spec("SADD", lambda r: ["SADD", gen_key(r)] + gen_members(r, r.randrange(0, 512)))
add_spec("SREM", lambda r: ["SREM", gen_key(r)] + gen_members(r, r.randrange(0, 512)))
add_spec("SCARD", lambda r: ["SCARD", gen_key(r)])
add_spec("SMEMBERS", lambda r: ["SMEMBERS", gen_key(r)])
add_spec("SISMEMBER", lambda r: ["SISMEMBER", gen_key(r), gen_value(r)])
add_spec("SMISMEMBER", lambda r: ["SMISMEMBER", gen_key(r)] + gen_members(r, r.randrange(0, 512)))
add_spec("SPOP", lambda r: ["SPOP", gen_key(r)] + ([str(r.randrange(0, 100000))] if r.random() < 0.6 else []))
add_spec("SRANDMEMBER", lambda r: ["SRANDMEMBER", gen_key(r)] + ([gen_int(r)] if r.random() < 0.6 else []))
add_spec("SMOVE", lambda r: ["SMOVE", gen_key(r), gen_key(r), gen_value(r)])
add_spec("SDIFF", lambda r: ["SDIFF"] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SDIFFSTORE", lambda r: ["SDIFFSTORE", gen_key(r)] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SINTER", lambda r: ["SINTER"] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SINTERSTORE", lambda r: ["SINTERSTORE", gen_key(r)] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SUNION", lambda r: ["SUNION"] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SUNIONSTORE", lambda r: ["SUNIONSTORE", gen_key(r)] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("SSCAN", lambda r: ["SSCAN", gen_key(r), gen_int(r)] + (["MATCH", gen_pattern(r)] if r.random() < 0.6 else []) + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.6 else []))

# Zsets
add_spec("ZADD", lambda r: ["ZADD", gen_key(r)] + (["NX"] if r.random() < 0.2 else []) + (["XX"] if r.random() < 0.2 else []) + (["CH"] if r.random() < 0.2 else []) + (["INCR"] if r.random() < 0.2 else []) + gen_zadd_pairs(r, r.randrange(0, 256)))
add_spec("ZREM", lambda r: ["ZREM", gen_key(r)] + gen_members(r, r.randrange(0, 512)))
add_spec("ZCARD", lambda r: ["ZCARD", gen_key(r)])
add_spec("ZCOUNT", lambda r: ["ZCOUNT", gen_key(r), gen_float(r), gen_float(r)])
add_spec("ZSCORE", lambda r: ["ZSCORE", gen_key(r), gen_value(r)])
add_spec("ZRANK", lambda r: ["ZRANK", gen_key(r), gen_value(r)])
add_spec("ZREVRANK", lambda r: ["ZREVRANK", gen_key(r), gen_value(r)])
add_spec("ZRANGE", lambda r: ["ZRANGE", gen_key(r), gen_int(r), gen_int(r)] + (["WITHSCORES"] if r.random() < 0.4 else []))
add_spec("ZREVRANGE", lambda r: ["ZREVRANGE", gen_key(r), gen_int(r), gen_int(r)] + (["WITHSCORES"] if r.random() < 0.4 else []))
add_spec("ZRANGEBYSCORE", lambda r: ["ZRANGEBYSCORE", gen_key(r), gen_float(r), gen_float(r)] + (["LIMIT", gen_int(r), gen_int(r)] if r.random() < 0.5 else []) + (["WITHSCORES"] if r.random() < 0.4 else []))
add_spec("ZREVRANGEBYSCORE", lambda r: ["ZREVRANGEBYSCORE", gen_key(r), gen_float(r), gen_float(r)] + (["LIMIT", gen_int(r), gen_int(r)] if r.random() < 0.5 else []) + (["WITHSCORES"] if r.random() < 0.4 else []))
add_spec("ZLEXCOUNT", lambda r: ["ZLEXCOUNT", gen_key(r), random.choice(["-","[a","(a","[z","+"]), random.choice(["+","[z","(z","[a","-"])])
add_spec("ZRANGEBYLEX", lambda r: ["ZRANGEBYLEX", gen_key(r), random.choice(["-","[a","(a","[z","+"]), random.choice(["+","[z","(z","[a","-"])])
add_spec("ZREVRANGEBYLEX", lambda r: ["ZREVRANGEBYLEX", gen_key(r), random.choice(["+","[z","(z","[a","-"]), random.choice(["-","[a","(a","[z","+"])])
add_spec("ZSCAN", lambda r: ["ZSCAN", gen_key(r), gen_int(r)] + (["MATCH", gen_pattern(r)] if r.random() < 0.6 else []) + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.6 else []))
add_spec("ZPOPMAX", lambda r: ["ZPOPMAX", gen_key(r)] + ([str(r.randrange(0, 100000))] if r.random() < 0.6 else []))
add_spec("ZPOPMIN", lambda r: ["ZPOPMIN", gen_key(r)] + ([str(r.randrange(0, 100000))] if r.random() < 0.6 else []))
add_spec("ZRANDMEMBER", lambda r: ["ZRANDMEMBER", gen_key(r)] + ([gen_int(r)] if r.random() < 0.7 else []) + (["WITHSCORES"] if r.random() < 0.4 else []))
add_spec("ZINCRBY", lambda r: ["ZINCRBY", gen_key(r), gen_float(r), gen_value(r)])
add_spec("ZREMRANGEBYRANK", lambda r: ["ZREMRANGEBYRANK", gen_key(r), gen_int(r), gen_int(r)])
add_spec("ZREMRANGEBYSCORE", lambda r: ["ZREMRANGEBYSCORE", gen_key(r), gen_float(r), gen_float(r)])
add_spec("ZREMRANGEBYLEX", lambda r: ["ZREMRANGEBYLEX", gen_key(r), random.choice(["-","[a","(a","[z","+"]), random.choice(["+","[z","(z","[a","-"])])
add_spec("ZMSCORE", lambda r: ["ZMSCORE", gen_key(r)] + gen_members(r, r.randrange(0, 512)))
add_spec("ZINTER", lambda r: gen_zinter_union(r, "ZINTER"))
add_spec("ZUNION", lambda r: gen_zinter_union(r, "ZUNION"))
add_spec("ZINTERSTORE", lambda r: ["ZINTERSTORE", gen_key(r)] + gen_zinter_union(r, "ZINTER")[1:])
add_spec("ZUNIONSTORE", lambda r: ["ZUNIONSTORE", gen_key(r)] + gen_zinter_union(r, "ZUNION")[1:])

# Streams
add_spec("XADD", lambda r: ["XADD", gen_key(r), random.choice(["*","0-0",gen_stream_id(r)])] + gen_field_value_list(r, r.randrange(0, 64)))
add_spec("XDEL", lambda r: ["XDEL", gen_key(r)] + gen_stream_ids(r, r.randrange(0, 512)))
add_spec("XLEN", lambda r: ["XLEN", gen_key(r)])
add_spec("XRANGE", lambda r: ["XRANGE", gen_key(r), random.choice(["-","0-0",gen_stream_id(r)]), random.choice(["+","$",gen_stream_id(r)])] + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.5 else []))
add_spec("XREVRANGE", lambda r: ["XREVRANGE", gen_key(r), random.choice(["+","$",gen_stream_id(r)]), random.choice(["-","0-0",gen_stream_id(r)])] + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.5 else []))
add_spec("XGROUP", gen_xgroup)
add_spec("XREADGROUP", gen_xreadgroup)
add_spec("XREAD", lambda r: ["XREAD"] + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.7 else []) + (["BLOCK", str(r.randrange(0, 100000))] if r.random() < 0.5 else []) + ["STREAMS", gen_key(r), random.choice(["$","0-0",gen_stream_id(r)])])
add_spec("XPENDING", lambda r: ["XPENDING", gen_key(r), random.choice(GROUPS)] + ([random.choice(["-","+"]), random.choice(["-","+"]), str(r.randrange(0, 100000))] if r.random() < 0.5 else []))
add_spec("XINFO", lambda r: ["XINFO", random.choice(["STREAM","GROUPS","CONSUMERS"]), gen_key(r)] + ([random.choice(GROUPS), random.choice(CONSUMERS)] if r.random() < 0.3 else []))
add_spec("XACK", lambda r: ["XACK", gen_key(r), random.choice(GROUPS)] + gen_stream_ids(r, r.randrange(0, 512)))
add_spec("XCLAIM", lambda r: ["XCLAIM", gen_key(r), random.choice(GROUPS), random.choice(CONSUMERS), str(r.randrange(0, 100000))] + gen_stream_ids(r, r.randrange(0, 128)) + (["JUSTID"] if r.random() < 0.3 else []))
add_spec("XAUTOCLAIM", lambda r: ["XAUTOCLAIM", gen_key(r), random.choice(GROUPS), random.choice(CONSUMERS), str(r.randrange(0, 100000)), random.choice(["0-0",gen_stream_id(r),"$"])] + (["COUNT", str(r.randrange(0, 100000))] if r.random() < 0.7 else []))
add_spec("XSETID", lambda r: ["XSETID", gen_key(r), random.choice(["0-0","$",gen_stream_id(r)])] + (["ENTRIESADDED", gen_int(r)] if r.random() < 0.4 else []))
add_spec("XTRIM", lambda r: ["XTRIM", gen_key(r), random.choice(["MAXLEN","MINID"]), random.choice(["~","=",""]), str(r.randrange(0, 100000))] + (["LIMIT", str(r.randrange(0, 100000))] if r.random() < 0.5 else []))

# Your "vector-length" target (and friends)
add_spec("XACKDEL", lambda r: gen_xackdel_like(r, "XACKDEL"))

# PubSub
add_spec("PUBLISH", lambda r: ["PUBLISH", gen_channel(r), gen_value(r)])
add_spec("SUBSCRIBE", lambda r: ["SUBSCRIBE"] + [gen_channel(r) for _ in range(r.randrange(0, 64))])
add_spec("UNSUBSCRIBE", lambda r: ["UNSUBSCRIBE"] + [gen_channel(r) for _ in range(r.randrange(0, 64))])
add_spec("PSUBSCRIBE", lambda r: ["PSUBSCRIBE"] + [gen_pattern(r) for _ in range(r.randrange(0, 64))])
add_spec("PUNSUBSCRIBE", lambda r: ["PUNSUBSCRIBE"] + [gen_pattern(r) for _ in range(r.randrange(0, 64))])
add_spec("PUBSUB", lambda r: ["PUBSUB", random.choice(["CHANNELS","NUMSUB","NUMPAT"]), gen_pattern(r)] if r.random() < 0.7 else ["PUBSUB", random.choice(["HELP","SHARDCHANNELS","SHARDNUMSUB"])])

# Scripting
add_spec("EVAL", gen_minimal_eval)
add_spec("EVALSHA", lambda r: ["EVALSHA", mutate_string("0"*40, r), random.choice(["0","1","2"])] + ([gen_key(r)] if r.random() < 0.5 else []) + ([gen_value(r)] if r.random() < 0.5 else []))
add_spec("SCRIPT", lambda r: ["SCRIPT", random.choice(["LOAD","EXISTS","FLUSH","KILL","HELP"]), gen_value(r)] if r.random() < 0.6 else ["SCRIPT", "HELP"])

# Scans
add_spec("SCAN", lambda r: gen_scan_like(r, "SCAN"))
add_spec("HSCAN", lambda r: gen_scan_like(r, "HSCAN"))  # overwritten above but fine
add_spec("SSCAN", lambda r: gen_scan_like(r, "SSCAN"))  # overwritten above but fine
add_spec("ZSCAN", lambda r: gen_scan_like(r, "ZSCAN"))  # overwritten above but fine

# Multi/exec
add_spec("MULTI", lambda r: ["MULTI"])
add_spec("EXEC", lambda r: ["EXEC"])
add_spec("DISCARD", lambda r: ["DISCARD"])
add_spec("WATCH", lambda r: ["WATCH"] + [gen_key(r) for _ in range(r.randrange(0, 64))])
add_spec("UNWATCH", lambda r: ["UNWATCH"])

# M* (bulk)
add_spec("MGET", lambda r: ["MGET"] + [gen_key(r) for _ in range(r.randrange(0, 256))])
add_spec("MSET", lambda r: ["MSET"] + gen_kv_pair_list(r, r.randrange(0, 128)))
add_spec("MSETNX", lambda r: ["MSETNX"] + gen_kv_pair_list(r, r.randrange(0, 128)))

# -------------------------
# Generic fallback generation (for commands we didn't spec)
# -------------------------

GENERIC_MODES = ["none", "key", "key_key", "key_int", "key_val", "key_field", "key_field_val", "pattern", "ints", "vals"]

def gen_generic(cmdname: str, rng: random.Random) -> List[str]:
    # Always include known command name (uppercase); args are best-effort plausible
    mode = rng.choice(GENERIC_MODES)

    if mode == "none":
        return [cmdname]
    if mode == "key":
        return [cmdname, gen_key(rng)]
    if mode == "key_key":
        return [cmdname, gen_key(rng), gen_key(rng)]
    if mode == "key_int":
        return [cmdname, gen_key(rng), gen_int(rng)]
    if mode == "key_val":
        return [cmdname, gen_key(rng), gen_value(rng)]
    if mode == "key_field":
        return [cmdname, gen_key(rng), gen_field(rng)]
    if mode == "key_field_val":
        return [cmdname, gen_key(rng), gen_field(rng), gen_value(rng)]
    if mode == "pattern":
        return [cmdname, gen_pattern(rng)]
    if mode == "ints":
        n = rng.randrange(0, 32)
        return [cmdname] + [gen_int(rng) for _ in range(n)]
    # vals
    n = rng.randrange(0, 64)
    return [cmdname] + [gen_value(rng) for _ in range(n)]

def gen_any_command(rng: random.Random) -> List[str]:
    name = rng.choice(ALL_COMMANDS_UP)
    # Special: "host:" from grep is weird. Still generate it as a bare token sometimes.
    if name == "HOST:":
        if rng.random() < 0.5:
            return ["HOST:", gen_value(rng)]
        return ["HOST:"]
    if name in SPECS and rng.random() < 0.85:
        return SPECS[name].gen(rng)
    return gen_generic(name, rng)

# -------------------------
# Mutations
# -------------------------

def mutate_int_str(s: str, rng: random.Random) -> str:
    if rng.random() < 0.75:
        try:
            v = int(s, 10)
            if rng.random() < 0.3:
                v = int(random.choice([
                    -1,0,1,7,8,9,15,16,31,32,63,64,127,128,255,256,1024,4096,
                    2**31-1, -(2**31), 2**63-1, -(2**63)
                ]))
            else:
                v += rng.randrange(-4096, 4097)
            return str(v)
        except Exception:
            pass
    return random.choice(TOKENS)

def mutate_string(s: str, rng: random.Random) -> str:
    if s is None:
        s = ""
    if not s:
        s = random.choice(TOKENS) or "A"
    action = rng.randrange(7)
    if action == 0:
        b = bytearray(s.encode("utf-8", errors="ignore"))
        if b:
            i = rng.randrange(len(b))
            b[i] ^= rng.randrange(1, 256)
        return b.decode("utf-8", errors="replace")
    if action == 1:
        if len(s) >= 2:
            i = rng.randrange(len(s))
            j = rng.randrange(i, len(s))
            sl = s[i:j] if j > i else s[i:i+1]
            return s[:i] + sl * rng.randrange(2, 40) + s[i:]
        return s + s
    if action == 2:
        if len(s) >= 2:
            i = rng.randrange(len(s))
            j = rng.randrange(i, len(s))
            return s[:i] + s[j:]
        return ""
    if action == 3:
        return random.choice(TOKENS + KEYS + FIELDS + VALUES + GROUPS + CONSUMERS)
    if action == 4:
        tail = "".join(chr(rng.randrange(32, 127)) for _ in range(rng.randrange(1, 256)))
        return s + tail
    if action == 5:
        return s[:rng.randrange(0, len(s)+1)]
    # action == 6:
    return s + "\x00" * rng.randrange(0, 32)

def mutate_varlen_stream_ids(argv: List[str], rng: random.Random) -> List[str]:
    """
    Aggressively explores 'list of stream IDs' style commands:
      XACK key group id [id ...]
      XDEL key id [id ...]
      XACKDEL key group IDS N id...
    """
    if not argv:
        return argv
    cmd = argv[0].upper()
    out = argv[:]

    if cmd == "XACKDEL":
        # normalize then explode
        stream = out[1] if len(out) > 1 else gen_key(rng)
        group  = out[2] if len(out) > 2 else random.choice(GROUPS)
        # pick dangerous counts often
        n = rng.choice([0,1,2,7,8,9,10,15,16,17,31,32,64,65,128,256])
        # mismatch is valuable
        ids_len = n
        if rng.random() < 0.4:
            ids_len = max(0, min(n + rng.randrange(1, 128), 512))
        if rng.random() < 0.2:
            ids_len = max(0, min(max(0, n // 2), 512))
        ids = gen_stream_ids(rng, ids_len)
        return ["XACKDEL", stream, group, "IDS", str(n)] + ids

    # XACK key group id...
    if cmd == "XACK":
        stream = out[1] if len(out) > 1 else gen_key(rng)
        group  = out[2] if len(out) > 2 else random.choice(GROUPS)
        n = rng.choice([0,1,2,7,8,9,10,15,16,17,31,32,64,65,128,512])
        ids = gen_stream_ids(rng, min(n, 512))
        if rng.random() < 0.3:
            ids = ids * rng.randrange(2, 20)
        return ["XACK", stream, group] + ids[:MAX_ARGS]

    # XDEL key id...
    if cmd == "XDEL":
        stream = out[1] if len(out) > 1 else gen_key(rng)
        n = rng.choice([0,1,2,7,8,9,10,15,16,17,31,32,64,65,128,512])
        ids = gen_stream_ids(rng, min(n, 512))
        if rng.random() < 0.3:
            ids = ids * rng.randrange(2, 20)
        return ["XDEL", stream] + ids[:MAX_ARGS]

    return out

def mutate_one_command(argv: List[str], rng: random.Random) -> List[str]:
    if not argv:
        return argv

    out = argv[:]
    cmd0 = out[0].upper()

    # Occasionally replace the whole command with a freshly generated one
    if rng.random() < 0.18:
        return gen_any_command(rng)

    # Special varlen stream-ID explosions
    if cmd0 in ("XACKDEL","XACK","XDEL") and rng.random() < 0.85:
        return mutate_varlen_stream_ids(out, rng)

    # Normalize command casing / occasionally corrupt it
    if rng.random() < 0.90:
        out[0] = cmd0
    else:
        out[0] = mutate_string(out[0], rng)

    # Mutate args by type-ish heuristics
    for i in range(1, len(out)):
        if rng.random() < 0.20:
            a = out[i]
            if re.fullmatch(r"-?\d+", a or ""):
                out[i] = mutate_int_str(a, rng)
            else:
                out[i] = mutate_string(a, rng)

    # Arg count mutations (insert/delete/duplicate slices)
    if rng.random() < 0.22:
        pos = rng.randrange(1, len(out)+1)
        # out.insert(pos, random.choice(TOKENS + KEYS + FIELDS + VALUES))
        choice_pool = TOKENS + KEYS + FIELDS + VALUES
        if rng.random() < 0.3:
            choice_pool += REDIS_OPTIONS
        out.insert(pos, rng.choice(choice_pool))
    if rng.random() < 0.15 and len(out) > 1:
        pos = rng.randrange(1, len(out))
        del out[pos]
    if rng.random() < 0.12 and len(out) > 2:
        i = rng.randrange(1, len(out))
        j = rng.randrange(i, len(out))
        sl = out[i:j] if j > i else [out[i]]
        pos = rng.randrange(1, len(out)+1)
        out[pos:pos] = sl * rng.randrange(2, 40)

    # Occasionally "explode" very vararg-ish commands
    if cmd0 in ("MSET","SADD","ZADD","DEL","UNLINK","EXISTS","MGET","HDEL","HMGET","ZREM") and rng.random() < 0.35:
        # append a bunch of plausible args
        extra = rng.randrange(0, 512)
        if cmd0 == "MSET":
            out += gen_kv_pair_list(rng, extra // 2)
        elif cmd0 == "ZADD":
            out += gen_zadd_pairs(rng, extra // 2)
        elif cmd0 in ("DEL","UNLINK","EXISTS","MGET"):
            out += [gen_key(rng) for _ in range(extra)]
        elif cmd0 in ("HDEL","HMGET"):
            out += [gen_field(rng) for _ in range(extra)]
        else:
            out += [gen_value(rng) for _ in range(extra)]

    if len(out) > MAX_ARGS:
        out = out[:MAX_ARGS]
    return out

def mutate_program(cmds: List[List[str]], rng: random.Random) -> List[List[str]]:
    cmds = [c[:] for c in cmds if c]

    # Bootstrap empty inputs with a small program
    if not cmds:
        cmds = [gen_any_command(rng) for _ in range(rng.randrange(1, 8))]

    action = rng.randrange(8)

    if action == 0:
        idx = rng.randrange(len(cmds))
        cmds[idx] = mutate_one_command(cmds[idx], rng)

    elif action == 1:
        n = rng.randrange(1, min(8, len(cmds)) + 1)
        for _ in range(n):
            idx = rng.randrange(len(cmds))
            cmds[idx] = mutate_one_command(cmds[idx], rng)

    elif action == 2:
        idx = rng.randrange(len(cmds)+1)
        cmds.insert(idx, gen_any_command(rng))

    elif action == 3 and len(cmds) > 1:
        del cmds[rng.randrange(len(cmds))]

    elif action == 4:
        rng.shuffle(cmds)

    elif action == 5:
        # duplicate block
        i = rng.randrange(len(cmds))
        j = rng.randrange(i, len(cmds))
        block = cmds[i:j] if j > i else [cmds[i]]
        pos = rng.randrange(len(cmds)+1)
        cmds[pos:pos] = [b[:] for b in block] * rng.randrange(2, 30)

    elif action == 6:
        # "stream prelude" to reach deep stream code more often
        stream = gen_key(rng)
        group = random.choice(GROUPS)
        cmds.insert(0, ["XGROUP","CREATE",stream,group,"0-0","MKSTREAM"])
        cmds.insert(0, ["XADD",stream,"*","field1","value1"])
        # then add a huge XACKDEL
        cmds.append(gen_xackdel_like(rng, "XACKDEL"))

    else:
        # "mixed-mode": rewrite most commands into known command names (coverage on command table)
        for i in range(len(cmds)):
            if rng.random() < 0.6:
                cmds[i] = gen_any_command(rng)

    if len(cmds) > MAX_CMDS:
        cmds = cmds[:MAX_CMDS]
    return cmds

# -------------------------
# AFL++ API
# -------------------------
def init(seed: int):
    global _initialized
    _initialized = True

def deinit():
    global _initialized
    _initialized = False

def fuzz_count(buf: bytearray) -> int:
    return _mutation_count

def fuzz(buf: bytearray, add_buf, max_size: int) -> bytearray:
    if not _initialized:
        init(0)

    if not isinstance(buf, (bytes, bytearray)):
        buf = bytearray(b"PING\n")

    b = bytes(buf)
    rng = rng_from_buf(b)
    cmds = parse_inline(b)

    # splice by command boundaries
    if add_buf and isinstance(add_buf, (bytes, bytearray)) and rng.random() < 0.25:
        other = parse_inline(bytes(add_buf))
        if other:
            cut1 = rng.randrange(0, len(cmds)+1) if cmds else 0
            cut2 = rng.randrange(0, len(other)+1)
            cmds = (cmds[:cut1] if cmds else []) + other[cut2:]

    mutated = mutate_program(cmds, rng)

    if FMT == "resp":
        out = render_resp_strict(mutated)
    else:
        out = render_inline(mutated, rng)

    if len(out) > max_size:
        out = out[:max_size]
    return bytearray(out)