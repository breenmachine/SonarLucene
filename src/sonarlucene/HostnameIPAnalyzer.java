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

import java.util.regex.Pattern;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.pattern.PatternTokenizer;

/**
 *
 * @author breens
 */
public class HostnameIPAnalyzer extends Analyzer {


    /* This is the only function that we need to override for our analyzer.
     * It takes in a java.io.Reader object and saves the tokenizer and list
     * of token filters that operate on it. 
     */
    @Override
    protected TokenStreamComponents createComponents(String field) {
        Tokenizer tokenizer = new PatternTokenizer(Pattern.compile("(((?!-)[A-Za-z0-9-_]{1,63}(?<!-)\\.)+[A-Za-z]{2,6})|(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"),0);
        TokenStream filter = new IPHostNameTokenFilter(tokenizer);
        return new TokenStreamComponents(tokenizer, filter);
    }
    
}
