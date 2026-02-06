package dk.brics.automaton;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.sqlite.JDBC;


public class DataLoadSave {
	
	private static final Pattern SNORT_RULE_PATTERN_REGEX = Pattern.compile("(?:pcre|regex):!?\"/((?:\\\\.|[^/\"\\\\])*)/([A-Za-z]*)\"");
	private static ArrayList<RPattern> loadSnortRulesPatternFromFiles(List<Path> paths) throws IOException {
		ArrayList<RPattern> rpatterns = new ArrayList<RPattern>();
		for (Path path : paths) {
			String pathStr = path.toString();
			String content = Files.readString(path, StandardCharsets.UTF_8);
			Matcher matcher = SNORT_RULE_PATTERN_REGEX.matcher(content);
			int lastStart = 0, line = 1;
			while (matcher.find()) {
				String pattern = matcher.group(1);
				String flags = matcher.group(2);
				for (; lastStart < matcher.start(); ++lastStart)
					if (content.charAt(lastStart) == '\n')
						++line;
				rpatterns.add(new RPattern(pattern, flags, pathStr + ':' + line));
			}
		}
		return rpatterns;
	}

	static ArrayList<RPattern> loadSnortRulesPattern(Path path) throws IOException {
		return loadSnortRulesPatternFromFiles(Collections.singletonList(path));
	}

	static ArrayList<Path> rListDir(Path path, String suffix) throws IOException {
		ArrayList<Path> result = new ArrayList<Path>();
		Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(Path child, BasicFileAttributes attrs) {
				if (!attrs.isDirectory() && child.toString().endsWith(suffix))
					result.add(child);
				return FileVisitResult.CONTINUE;
			}
		});
		return result;
	}

	static ArrayList<RPattern> loadSnortRulesDirPattern(Path path) throws IOException {
		return loadSnortRulesPatternFromFiles(rListDir(path, ".rules"));
	}

	static ArrayList<RPattern> loadJsonPattern(Path path) throws IOException, JSONException {
		String pathStr = path.toString();
		String content = Files.readString(path, StandardCharsets.UTF_8);
		JSONArray jsonArray = new JSONArray(content);
		ArrayList<RPattern> rpatterns = new ArrayList<RPattern>();
		rpatterns.ensureCapacity(jsonArray.length());
		for (int i = 0, n = jsonArray.length(); i < n; ++i) {
			JSONObject jsonObj = jsonArray.getJSONObject(i);
			rpatterns.add(new RPattern(jsonObj.getString("pattern"), null, pathStr + " [" + i + "]"));
		}
		return rpatterns;
	}


	static ArrayList<RPattern> loadSqlColumnPattern(
		String protocol, String db, 
		String table,
		String patternColumn, String flagsColumn
	) throws SQLException {
		Connection conn = null;
		Statement stmtSize = null, stmtData = null;
		try {
			conn = DriverManager.getConnection("jdbc:" + protocol + ":" + db);
			stmtSize = conn.createStatement();
			ResultSet rsSize = stmtSize.executeQuery("SELECT COUNT(" + patternColumn + ") FROM " + table);
			rsSize.next();
			int size = rsSize.getInt(1);
			ArrayList<RPattern> result = new ArrayList<RPattern>();
			result.ensureCapacity(size);
			String sourcePrefix = protocol + ':' + db;
			int i = 0;
			stmtData = conn.createStatement();
			if (flagsColumn != null) {
				ResultSet rsData = stmtData.executeQuery("SELECT " + patternColumn + ", " +  flagsColumn + " FROM " + table);
				while (rsData.next())
					result.add(new RPattern(rsData.getString(1), rsData.getString(2), sourcePrefix + '[' + (i++) + ']'));
			} else {
				ResultSet rsData = stmtData.executeQuery("SELECT " + patternColumn + " FROM " + table);
				while (rsData.next())
					result.add(new RPattern(rsData.getString(1), null, sourcePrefix + '[' + (i++) + ']'));
			}
			return result;
		} finally {
			if (conn != null && !conn.isClosed())
				conn.close();
			if (stmtSize != null && !stmtSize.isClosed())
				stmtSize.close();
			if (stmtSize != null && !stmtData.isClosed())
				stmtData.close();
		}
	}

	static ArrayList<RPattern> loadSqlColumnPatternRaw(String protclDbTblCol)
	throws SQLException, IllegalArgumentException {
		// format <protocol>:<db>:<table>.<column>
		int length = protclDbTblCol.length();
		int colonIndex1 = protclDbTblCol.indexOf(':', 0);
		if (colonIndex1 < 0 || colonIndex1 >= length - 1)
			throw new IllegalArgumentException("invalid <protcl>:<db>:<tbl>.<col> string");
		int colonIndex2 = protclDbTblCol.indexOf(':', colonIndex1 + 1);
		if (colonIndex2 < 0 || colonIndex2 >= length - 1)
			throw new IllegalArgumentException("invalid <protcl>:<db>:<tbl>.<col> string");
		int dotIndex = protclDbTblCol.indexOf('.', colonIndex2 + 1);
		if (dotIndex < 0)
			throw new IllegalArgumentException("invalid <protcl>:<db>:<tbl>.<col> string");
		String protocol = protclDbTblCol.substring(0, colonIndex1);
		String db = protclDbTblCol.substring(colonIndex1 + 1, colonIndex2);
		String table = protclDbTblCol.substring(colonIndex2 + 1, dotIndex);
		String column = protclDbTblCol.substring(dotIndex + 1);
		return loadSqlColumnPattern(protocol, db, table, column, null);
	}
 
	// static ArrayList<String> loadSqliteColumnPattern(String dbTblCol) throws SQLException {
	//	 final String NAME_GROUP = "([^\"\\.\\[`:]+|\"(?:[^\"]|\"\")+\"|`(?:[^`]|``)+`|\\[[^\\]]+\\])";
	//	 Pattern regex = Pattern.compile("((?:[A-Z]:)?[^:]*):" + NAME_GROUP + '.' + NAME_GROUP);
	//	 Matcher matcher = regex.matcher(dbTblCol);
	//	 if (!matcher.matches())  
	//		 throw new IllegalArgumentException("invalid dbTableCol " + dbTblCol);
	//	 String db = matcher.group(1);
	//	 String rawTable = matcher.group(2);
	//	 String rawColumn = matcher.group(3);
	//	 // FIXME
	//	 System.out.println(db + " " + rawTable + " " + rawColumn);
	//	 return loadSqliteColumnPatternRaw(db, rawTable, rawColumn);
	// }

	// static ArrayList<String> loadSqliteColumnPattern(String db, String table, String column) throws SQLException {
	//	 return loadSqliteColumnPatternRaw(db, quoteSqlName(table), quoteSqlName(column));
	// }


	// static String quoteSqlName(String name) {
	//	 return '"' + name.replace("\"", "\"\"") + '"';
	// }

	/*
	static String toTomlString(String s) {
		int nlIndex = s.indexOf('\n');
		if (s.indexOf("'''") < 0 && s.indexOf("\"\"\"") < 0) {
			if (nlIndex > 0 && s.indexOf('\\') < 0)
				return "\"\"\"\\\n" + s + "\"\"\"";
			else if (nlIndex < 0 && s.indexOf('\'') < 0)
				return '\'' + s + '\'';
			else
				return "'''" + s + "'''";
		} else {
			s = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'");
			String firstLineEnd = nlIndex > 0 ? "\\\n" : "";
			return "\"\"\"" + firstLineEnd + s + "\"\"\"";
		}
	}
	*/
	// private static Pattern TOML_CONTROL_CHAR_REGEX = Pattern.compile("[\u0000-\u0008\u000B-\u001F\u007F]|'''");
	static String toTomlString(String s) {
		boolean hasNewLine = false;
		boolean hasSingleQuote = false;
		boolean hasControl = false;
		for (int i = 0, n = s.length(); i < n; ++i) {
			char c = s.charAt(i);
			if (c == '\n')
				hasNewLine = true;
			else if (c == '\'')
				hasSingleQuote = true;
			else if (('\u0000' <= c && c <= '\u0008') || ('\u000B' <= c && c <= '\u001F') || c == '\u007F')
				hasControl = true;
		}
		boolean hasSingleQuote3 = hasSingleQuote && s.contains("'''");
		// If have control char or 3 single quotes, we need to escape them, then
		// we must use double quotes.
		if (hasControl || hasSingleQuote3) {
			StringBuilder builder = new StringBuilder();
			builder.append(hasNewLine ? "\"\"\"\n" : "\"");
			for (int i = 0, n = s.length(); i < n; ++i) {
				char c = s.charAt(i);
				if	  (c == '\b') builder.append("\\b");
				else if (c == '\t') builder.append("\\t");
				else if (c == '\f') builder.append("\\f");
				else if (c == '"')  builder.append("\\\"");
				else if (c == '\\') builder.append("\\\\");
				else if (('\u0000' <= c && c <= '\u0009') || ('\u000B' <= c && c <= '\u001F') || c == '\u007F') {
					String zeros =
						(c <= '\u000F') ? "000" :
						(c <= '\u00FF') ? "00" :
						(c <= '\u0FFF') ? "0" : "";
					builder.append("\\u").append(zeros).append(Integer.toHexString((int) c));
				} else
					builder.append(c);
			}
			builder.append(hasNewLine ? "\"\"\"" : "\"");
			return builder.toString();
		} else {
			return
				(hasNewLine ? "'''\n" : hasSingleQuote ? "'''" : "'") +
				s +
				(hasNewLine || hasSingleQuote ? "'''" : "'");
		}
	}

	// static <T> ArrayList<T> removeRepeat(ArrayList<T> list) {
	//	 ArrayList<T> result = new ArrayList<T>();
	//	 result.ensureCapacity(list.size());
	//	 HashSet<T> set = new HashSet<T>();
	//	 for (T e : list) {
	//		 if (!set.contains(e)) {
	//			 result.add(e);
	//			 set.add(e);
	//		 }
	//	 }
	//	 return result;
	// }

	static ArrayList<RPattern> mergeRepeatRPattern(List<RPattern> rpatterns) {
		ArrayList<RPattern> result = new ArrayList<RPattern>();
		result.ensureCapacity(rpatterns.size());  // half
		HashMap<String, RPattern> existings = new HashMap<String, RPattern>();
		for (RPattern rpattern : rpatterns) {
			String full = rpattern.toString();
			RPattern existing = existings.get(full);
			if (existing != null) {
				if (existing.source == null)
					existing.source = rpattern.source;
				else if (rpattern.source != null)
					existing.source += '\n' + rpattern.source;
			} else {
				existing = rpattern.clone();
				result.add(existing);
				existings.put(full, existing);
			}
		}
		return result;
	}

	static <T> ArrayList<T> arrayListJoin(List<ArrayList<T>> ll) {
		int total = 0;
		for (ArrayList<T> l : ll)
			total += l.size();
		ArrayList<T> result = new ArrayList<T>();
		result.ensureCapacity(total);
		for (ArrayList<T> l : ll)
			result.addAll(l);
		return result;
	}
}
