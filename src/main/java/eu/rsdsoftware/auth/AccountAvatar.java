package eu.rsdsoftware.auth;
import java.security.SecureRandom;
import java.util.*;
/** Fixed dark backgrounds provide readable white initials; colour is stored once per account. */
public final class AccountAvatar {
    public static final List<String> COLORS=List.of("#1e40af","#166534","#6b21a8","#9f1239","#92400e","#155e75");
    private static final SecureRandom RANDOM=new SecureRandom();
    private AccountAvatar() {}
    public static String randomColor() { return COLORS.get(RANDOM.nextInt(COLORS.size())); }
    public static String initials(String name) {
        var words=Arrays.stream((name==null?"":name).strip().split("\\s+"))
            .map(word->word.codePoints().filter(Character::isLetter).toArray()).filter(letters->letters.length>0).toList();
        if(words.isEmpty()) return "UU";
        int[] first=words.getFirst();
        int second=words.size()>1?words.getLast()[0]:first.length>1?first[1]:'U';
        return new String(new int[]{first[0],second},0,2).toUpperCase(Locale.ROOT).codePoints()
            .limit(2).collect(StringBuilder::new,StringBuilder::appendCodePoint,StringBuilder::append).toString();
    }
}
