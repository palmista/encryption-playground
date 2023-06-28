import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class IO {
    public static void writeToFile(File output, byte[] toWrite) 
    throws IllegalBlockSizeException, BadPaddingException, IOException{

    output.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();

}

public static byte[] getFileInBytes(File f) throws IOException{

    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
}
}
