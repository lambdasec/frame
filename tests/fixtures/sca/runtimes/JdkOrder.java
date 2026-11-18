import java.util.*;
public class JdkOrder {
    public static void main(String[] a) {
        String[] vs = {"8", "11", "11.0.33", "11.0.33.0.3", "17", "17.0.0.1", "17.0.3", "17.0.3.1", "17.0.20.1", "17.0.21",
                       "17.0.21.0.3", "17.0.21.1", "21.0.13", "21.0.13.0.3", "21.0.13.1", "25.0.4.1", "27-ea", "27",
                       "27.0.1", "27.0.1.0.3", "27.0.1.1", "17.0.21+9", "21.0.13+11-LTS", "26.0.2", "25.0.5.0.3"};
        StringBuilder sb = new StringBuilder();
        for (String x : vs) for (String y : vs) {
            int c = Integer.signum(Runtime.Version.parse(x).compareToIgnoreOptional(Runtime.Version.parse(y)));
            sb.append(x).append('\t').append(y).append('\t').append(c).append('\n');
        }
        System.out.print(sb);
    }
}
