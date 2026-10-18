"""Kernel and C vocabulary: names a rule author already knows.

The context-tier measurement asks which git context window at `Fix:` supplies
every literal token a rule requires. That question is only meaningful for tokens
that carry *information* -- an interface fact someone writing the rule would have
to look up. `memcpy` is not such a fact: it appears in thousands of files at any
fix revision, and a classifier that counted it would call it "outside the
commit" only because it happens not to occur in that rule's own `Files:`.

The gate for membership here is deliberately not a frequency threshold: **would
this name need documenting in the write-cve-rule skill?** `GFP_KERNEL`, `kfree`,
`EINVAL`, `spin_lock_irqsave` -- no. `bInterfaceCount`, `Ssid`, `follow_page`,
`LLCP_SAP_MAX` -- yes, and those are exactly what the measurement should count.

Frequency was used only to *generate candidates* (declared under `include/`, used
widely), never to decide. That test alone admits `is_last`, a common struct field
that is not an interface anyone documents, and rejects `skb_trim`, a core helper
whose use concentrates in networking. Every entry below was reviewed by hand.

Scope rule for the borderline cases: kernel-*wide* interfaces are in, subsystem
interfaces are out. `skb_trim` and `sysfs_emit` are real APIs but you have to know
which subsystem you are in to reach for them, so they stay out and keep counting
as context.
"""

# C library and compiler builtins that the kernel reimplements or wraps.
STRING_AND_MEMORY = frozenset(
    """
    memcpy memmove memset memcmp memchr memdup_user
    strcpy strncpy strlcpy strscpy strcat strncat strcmp strncmp strcasecmp
    strlen strnlen strchr strrchr strstr strsep strim kstrdup kstrndup kmemdup
    snprintf scnprintf sprintf vsnprintf sscanf simple_strtoul kstrtoint kstrtoul
    """.split()  # noqa: SIM905
)

# Allocation and release. kzalloc/kcalloc differ from kmalloc only in zeroing,
# which rules do care about -- but the *name* is not an interface fact.
ALLOCATION = frozenset(
    """
    kmalloc kzalloc kcalloc kmalloc_array kzalloc_node kmalloc_node krealloc
    kvmalloc kvzalloc kvcalloc kvmalloc_array vmalloc vzalloc
    kfree kvfree vfree kfree_sensitive kzfree kfree_rcu
    devm_kmalloc devm_kzalloc devm_kcalloc devm_kfree
    alloc_percpu free_percpu __get_free_page __get_free_pages free_page free_pages
    alloc_page alloc_pages __free_page __free_pages get_zeroed_page
    """.split()  # noqa: SIM905
)

GFP_FLAGS = frozenset(
    """
    GFP_KERNEL GFP_ATOMIC GFP_NOFS GFP_NOIO GFP_NOWAIT GFP_USER GFP_DMA GFP_DMA32
    GFP_HIGHUSER GFP_KERNEL_ACCOUNT __GFP_ZERO __GFP_NOWARN __GFP_NOFAIL
    __GFP_HIGHMEM __GFP_ACCOUNT
    """.split()  # noqa: SIM905
)

# errno constants. A rule that stars `return -EINVAL;` is saying something about
# control flow, not about which errno the author had to look up.
ERRNO = frozenset(
    """
    EINVAL ENOMEM EPERM EFAULT EBUSY ENODEV EAGAIN EWOULDBLOCK EIO ENOENT ENOSPC
    EOVERFLOW ERANGE EOPNOTSUPP ENOTSUPP EACCES EEXIST ENXIO EMSGSIZE EPROTO
    ETIMEDOUT EINTR ERESTARTSYS ENOSYS EBADF EBADMSG EPIPE EDOM ENOBUFS EADDRINUSE
    ENOTCONN ECONNRESET EDESTADDRREQ EAFNOSUPPORT EPROTONOSUPPORT ENETDOWN ELOOP
    ENAMETOOLONG EISDIR ENOTDIR EROFS EXDEV EFBIG ESRCH ECHILD EDEADLK ENOLINK
    """.split()  # noqa: SIM905
)

LIMITS = frozenset(
    """
    PAGE_SIZE PAGE_SHIFT PAGE_MASK PAGE_ALIGN
    INT_MAX INT_MIN UINT_MAX LONG_MAX LONG_MIN ULONG_MAX LLONG_MAX ULLONG_MAX
    SIZE_MAX SHRT_MAX USHRT_MAX CHAR_BIT BITS_PER_LONG BITS_PER_BYTE
    U8_MAX U16_MAX U32_MAX U64_MAX S8_MAX S16_MAX S32_MAX S64_MAX
    """.split()  # noqa: SIM905
)

LOCKING = frozenset(
    """
    spin_lock spin_unlock spin_lock_bh spin_unlock_bh spin_lock_irq spin_unlock_irq
    spin_lock_irqsave spin_unlock_irqrestore spin_trylock spin_lock_init
    raw_spin_lock raw_spin_unlock raw_spin_lock_irqsave raw_spin_unlock_irqrestore
    mutex_lock mutex_unlock mutex_trylock mutex_init mutex_lock_interruptible
    read_lock read_unlock write_lock write_unlock read_lock_bh write_lock_bh
    read_lock_irqsave read_unlock_irqrestore write_lock_irq write_unlock_irq
    down_read up_read down_write up_write down_write_trylock
    local_irq_save local_irq_restore local_irq_disable local_irq_enable
    local_bh_disable local_bh_enable preempt_disable preempt_enable
    """.split()  # noqa: SIM905
)

RCU = frozenset(
    """
    rcu rcu_read_lock rcu_read_unlock rcu_read_lock_bh rcu_read_unlock_bh
    call_rcu synchronize_rcu rcu_dereference rcu_dereference_protected
    rcu_assign_pointer rcu_barrier kfree_rcu_mightsleep
    """.split()  # noqa: SIM905
)

ATOMICS_AND_BARRIERS = frozenset(
    """
    READ_ONCE WRITE_ONCE barrier smp_mb smp_rmb smp_wmb mb rmb wmb
    smp_load_acquire smp_store_release
    atomic_read atomic_set atomic_inc atomic_dec atomic_add atomic_sub
    atomic_inc_return atomic_dec_return atomic_dec_and_test atomic_inc_not_zero
    atomic_cmpxchg atomic_xchg atomic_long_read atomic_long_set
    refcount_set refcount_inc refcount_dec refcount_dec_and_test refcount_inc_not_zero
    set_bit clear_bit test_bit test_and_set_bit test_and_clear_bit
    """.split()  # noqa: SIM905
)

LIST_HELPERS = frozenset(
    """
    list_add list_add_tail list_del list_del_init list_empty list_move list_move_tail
    list_first_entry list_first_entry_or_null list_last_entry list_next_entry
    list_entry list_for_each list_for_each_entry list_for_each_entry_safe
    list_for_each_entry_rcu list_for_each_safe INIT_LIST_HEAD LIST_HEAD list_splice
    hlist_add_head hlist_del hlist_del_init hlist_empty hlist_for_each_entry
    """.split()  # noqa: SIM905
)

# Macros and helpers that appear in every subsystem.
COMMON_MACROS = frozenset(
    """
    min max min_t max_t clamp clamp_t abs swap ALIGN IS_ALIGNED PTR_ALIGN
    roundup rounddown round_up round_down DIV_ROUND_UP DIV_ROUND_CLOSEST
    ARRAY_SIZE offsetof offsetofend container_of sizeof_field FIELD_SIZEOF
    BUILD_BUG_ON BUG BUG_ON WARN WARN_ON WARN_ON_ONCE WARN_ONCE
    likely unlikely IS_ERR IS_ERR_OR_NULL PTR_ERR ERR_PTR PTR_ERR_OR_ZERO ERR_CAST
    NULL true false
    pr_err pr_warn pr_info pr_debug pr_notice pr_cont
    dev_err dev_warn dev_info dev_dbg netdev_err netdev_warn
    """.split()  # noqa: SIM905
)

# Userspace boundary and capability checks. These are the kernel's own idiom for
# "is this allowed" and "copy across the boundary"; not facts to look up.
UACCESS_AND_CAPS = frozenset(
    """
    copy_to_user copy_from_user copy_to_user_nofault copy_from_user_nofault
    get_user put_user __get_user __put_user clear_user access_ok
    strncpy_from_user strnlen_user memdup_user_nul simple_read_from_buffer
    capable ns_capable file_ns_capable capable_wrt_inode_uidgid
    CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE CAP_DAC_OVERRIDE
    """.split()  # noqa: SIM905
)

VOCABULARY = frozenset().union(
    STRING_AND_MEMORY,
    ALLOCATION,
    GFP_FLAGS,
    ERRNO,
    LIMITS,
    LOCKING,
    RCU,
    ATOMICS_AND_BARRIERS,
    LIST_HELPERS,
    COMMON_MACROS,
    UACCESS_AND_CAPS,
)
