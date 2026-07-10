package edu.stonybrook.rewbguard;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

public class ExtractSnortDataset {
	public static void main(String[] args) throws IOException, ArgumentParserException {
		ArgumentParser parser = ArgumentParsers.newFor("ExtractSnortDataset").build()
			.description("Extract Snort dataset and generate JSON and TOML output files");
		parser.addArgument("-i", "--input")
			.help("Input Snort rules directory");
		parser.addArgument("-j", "--json")
			.setDefault("data/exp/snort2-register-regexes.json")
			.help("Output JSON file path (default: data/exp/snort2-register-regexes.json)");
		parser.addArgument("-t", "--toml")
			.setDefault("data/exp/snort2-register-regexes.toml")
			.help("Output TOML file path (default: data/exp/snort2-register-regexes.toml)");

		Namespace ns = parser.parseArgs(args);
		String inputDir = ns.getString("input");
		String jsonPath = ns.getString("json");
		String tomlPath = ns.getString("toml");

		ArrayList<RPattern> rpatterns = DataLoadSave.loadSnortRulesDirPattern(Paths.get(inputDir));
		rpatterns = DataLoadSave.mergeRepeatRPattern(rpatterns);
		JSONArray json = new JSONArray();
		StringBuilder toml = new StringBuilder();
		for (RPattern rpattern : rpatterns) {
			JSONObject jsonObj = new JSONObject();
			jsonObj.put("pattern", rpattern.pattern);
			jsonObj.put("flags", rpattern.flags);
			jsonObj.put("sources", rpattern.sources);
			json.put(jsonObj);

			toml
				.append("[regexes]\n")
				.append("pattern = ").append(DataLoadSave.toTomlString(rpattern.pattern)).append('\n')
				.append("flags = ").append(DataLoadSave.toTomlString(rpattern.flags)).append('\n')
				.append("sources = [\n");
			for (String source : rpattern.sources)
				toml.append("    ").append(DataLoadSave.toTomlString(source)).append(",\n");
			toml.append("]\n\n");
		}
		writeFile(jsonPath, json.toString(2));
		writeFile(tomlPath, toml);
	}

	private static void writeFile(String path, CharSequence content) throws IOException {
		try (Writer writer = Files.newBufferedWriter(Paths.get(path), StandardCharsets.UTF_8)) {
			if (content instanceof String)
				writer.write((String) content);
			else
				writer.append(content);
		}
	}
}
