/*
 * Copyright (C) 2016 breens
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
package sonarlucene;

import java.io.IOException;
import java.util.LinkedList;
import java.util.Queue;
import java.util.regex.Matcher;
import org.apache.lucene.analysis.TokenFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.apache.lucene.analysis.tokenattributes.PositionIncrementAttribute;
import java.util.regex.Pattern;

/**
 *
 * @author breens
 */
public class IPHostNameTokenFilter extends TokenFilter {
    private static Pattern ipPattern = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    private static Pattern hostPattern = Pattern.compile("(((?!-)[A-Za-z0-9-_]{1,63}(?<!-)\\.)+[A-Za-z]{2,6})");
    private static Pattern hostIpPattern = Pattern.compile("(((?!-)[A-Za-z0-9-_]{1,63}(?<!-)\\.)+[A-Za-z]{2,6})|(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
    private Queue<char[]> terms;
    
    public IPHostNameTokenFilter(TokenStream tokenStream) {
        super(tokenStream);
        terms = new LinkedList<char[]>();
    }

    protected CharTermAttribute charTermAttribute =
        addAttribute(CharTermAttribute.class);
    protected PositionIncrementAttribute positionIncrementAttribute =
        addAttribute(PositionIncrementAttribute.class);

    @Override
    public boolean incrementToken() throws IOException {
        if(!terms.isEmpty()){
            char[] buffer = terms.poll();
            charTermAttribute.setEmpty();
            charTermAttribute.copyBuffer(buffer, 0, buffer.length);
            positionIncrementAttribute.setPositionIncrement(0);
            return true;        
        }
        String nextToken = null;
        while (nextToken == null) {

            // Reached the end of the token stream being processed
            if ( ! this.input.incrementToken()) {
                return false;
            }

            // Get text of the current token and remove any
            // leading/trailing whitespace.
            String currentTokenInStream =
                this.input.getAttribute(CharTermAttribute.class)
                    .toString().trim();

            // Save the token if it matches an ip or hostname
            Matcher m = hostIpPattern.matcher(currentTokenInStream);
            if (m.matches()) {
                nextToken = currentTokenInStream;
            }
        }

        //if the token is hostname, split into components
        Matcher m = hostPattern.matcher(nextToken);
        if(m.matches())
        {
            this.charTermAttribute.setEmpty().append(nextToken);
            this.positionIncrementAttribute.setPositionIncrement(1);
            String[] domainComponents = nextToken.split("\\.");
            for(int i=0;i<domainComponents.length-1;i++){
                if(domainComponents[i].length() > 3){
                    this.terms.add(domainComponents[i].toCharArray());
                }
            }
        }
        else //assume ip and split into class B, C and original
        {
            this.charTermAttribute.setEmpty().append(nextToken);
            this.positionIncrementAttribute.setPositionIncrement(1);
            
            //Shouldn't have to break an IP address up, because we always search for IP's from the front!
            /*String classC = nextToken.substring(0,nextToken.lastIndexOf((int)'.'));
            this.terms.add(classC.toCharArray());
            
            String classB = classC.substring(0,classC.lastIndexOf((int)'.'));
            this.terms.add(classB.toCharArray());*/
        }
       

        return true;
    }
    
}
