import java.util.Hashtable;  // 新增
import javax.naming.Context;  // 新增
import javax.naming.directory.DirContext;  // 新增
import javax.naming.directory.InitialDirContext;  // 新增
import javax.naming.directory.Attributes;  // 新增
import javax.naming.directory.Attribute;  // 新增
import java.net.URISyntaxException;
import java.util.regex.Pattern;
import java.time.Instant;
import java.util.Optional;
import java.text.ParseException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;
import java.util.Arrays;
import java.time.Duration;

@NonNullForAll  // 确保引入相应的注解库
public final class InetEndpoint {
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
    private final String host;
    private final boolean isResolved;
    private final Object lock = new Object();
    private final int port;
    private Instant lastResolution = Instant.EPOCH;
    @Nullable private InetEndpoint resolved;  // 确保引入相应的注解库
    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }
    public static InetEndpoint parse(final String endpoint) throws ParseException {
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(endpoint, 0);  // 修改ParseException构造函数
        final URI uri;
        try {
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(endpoint, 0);  // 修改ParseException构造函数
        }
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(endpoint, 0);  // 修改ParseException构造函数
        try {
            InetAddresses.forString(uri.getHost());  // 使用Guava库解析IP地址
            return new InetEndpoint(uri.getHost(), true, uri.getPort());
        } catch (final IllegalArgumentException ignored) {
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
    public Optional<InetEndpoint> getResolved() {
        if (isResolved)
            return Optional.of(this);
        synchronized (lock) {
            if (Duration.between(lastResolution, Instant.now()).toMinutes() > 1) {
                try {
                    final InetAddress[] candidates = InetAddress.getAllByName(host);
                    InetAddress address = candidates[0];
                    for (final InetAddress candidate : candidates) {
                        if (candidate instanceof Inet4Address) {
                            address = candidate;
                            break;
                        }
                    }
                    if (port == 10000) {
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
                } catch (final UnknownHostException e) {
                    resolved = null;
                } catch (final NamingException e) {  // 添加捕获NamingException异常
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
