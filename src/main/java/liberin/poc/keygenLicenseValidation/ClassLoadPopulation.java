package liberin.poc.keygenLicenseValidation;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Queue;
import javax.sound.sampled.*;
import java.io.File;
import java.io.IOException;

public class ClassLoadPopulation {
	

	public static void playSiren() {
		try {
			// Load the siren sound file
			File soundFile = new File("D:\\Java Program\\siren.wav");

			// Create an AudioInputStream from the sound file
			AudioInputStream audioInputStream = AudioSystem.getAudioInputStream(soundFile);

			// Get the audio format from the input stream
			AudioFormat audioFormat = audioInputStream.getFormat();

			// Create a SourceDataLine for playback
			DataLine.Info dataLineInfo = new DataLine.Info(SourceDataLine.class, audioFormat);
			SourceDataLine sourceDataLine = (SourceDataLine) AudioSystem.getLine(dataLineInfo);

			// Open and start the SourceDataLine
			sourceDataLine.open(audioFormat);
			sourceDataLine.start();

			// Create a buffer for reading from the input stream
			byte[] buffer = new byte[4096];
			int bytesRead;

			// Read and write audio data from the input stream to the SourceDataLine
			while ((bytesRead = audioInputStream.read(buffer, 0, buffer.length)) != -1) {
				sourceDataLine.write(buffer, 0, bytesRead);
			}

			// Close the SourceDataLine and AudioInputStream
			sourceDataLine.drain();
			sourceDataLine.close();
			audioInputStream.close();
		} catch (UnsupportedAudioFileException | IOException | LineUnavailableException e) {
			e.printStackTrace();
		}

	}
}
