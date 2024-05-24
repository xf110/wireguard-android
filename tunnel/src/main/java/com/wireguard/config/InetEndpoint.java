import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import java.net.URISyntaxException;
import java.util.regex.Pattern;
import java.time.Instant;
import java.time.Duration;
import java.util.Optional;
import java.text.ParseException;
import java.util.Arrays;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;

/**
 * 一个用于连接到WireGuard {@link Peer} 的外部端点（主机和端口）。
 * <p>
 * 此类的实例是外部不可变的。
 */
@NonNullForAll
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;

    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }

    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class.getName(), endpoint, 0);
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(e.getMessage(), 0);
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException("缺失/无效的端口号", 0);
        try {
            InetAddresses.parse(uri.getHost());
            // 解析主机为数字地址成功，因此不需要进行DNS查找。
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final ParseException ignored) {
            // 解析主机为数字地址失败，因此它必须是DNS主机名/FQDN。
            return new InetEndpoint(uri.getHost(), false, uri.getPort());
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint))
            return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    /**
     * 生成一个 {@code InetEndpoint} 实例，具有相同的端口，并使用DNS解析的主机转换为数字地址。
     * 如果主机已经是数字地址，则可能返回现有实例。因为此函数可能执行网络I/O，所以不能从主线程调用。
     *
     * @return 解析的端点，或 {@link Optional#empty()}
     */
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            // TODO: 使用DNS TTL实现一个真正的超时机制
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    // 优先使用v4端点以解决DNS64和IPv6 NAT问题。
                    final InetAddress[] candidates = InetAddress.getAllByName(host);
                    InetAddress address = candidates[0];
                    for (final InetAddress candidate : candidates) {
                        if (candidate instanceof Inet4Address) {
                            address = candidate;
                            break;
                        }
                    }

                    if (port == 10000) {
                        // 使用InitialDirContext查询TXT记录
                        Hashtable<String, String> env = new Hashtable<>();
                        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
                        DirContext ctx = new InitialDirContext(env);
                        Attributes attrs = ctx.getAttributes("dns:/" + host, new String[]{"TXT"});
                        Attribute attr = attrs.get("TXT");
                        if (attr != null) {
                            String txtRecord = (String) attr.get();
                            String[] parts = txtRecord.split(":");
                            if (parts.length == 2) {
                                String resolvedHost = parts[0];
                                int resolvedPort = Integer.parseInt(parts[1]);
                                resolved = new InetEndpoint(resolvedHost, true, resolvedPort);
                                lastResolution = Instant.now();
                                return Optional.of(resolved);
                            }
                        }
                    }

                    if (address instanceof Inet6Address) {
                        byte[] v6 = address.getAddress();
                        if ((v6[0] == 0x20) && (v6[1] == 0x01) && (v6[2] == 0x00) && (v6[3] == 0x00)) {
                            InetAddress v4 = InetAddress.getByAddress(Arrays.copyOfRange(v6, 12, 16));
                            int p = ((v6[10] & 0xFF) << 8) | (v6[11] & 0xFF);
                            resolved = new InetEndpoint(v4.getHostAddress(), true, p);
                        }
                    }

                    if (resolved == null)
                        resolved = new InetEndpoint(address.getHostAddress(), true, port);
                    lastResolution = Instant.now();
                } catch (final UnknownHostException | NamingException e) {
                    resolved = null;
                }
            }
            return Optional.ofNullable(resolved);
        }
    }

    @Override
    public int hashCode() {
        return host.hashCode() ^ port;
    }

    @Override
    public String toString() {
        final boolean isBareIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isBareIpv6 ? '[' + host + ']' : host) + ':' + port;
    }
}
