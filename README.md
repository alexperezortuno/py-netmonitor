# Net Monitor

## Description
This is a simple network monitor that
- Monitors the network traffic on the device
- Shows the network traffic in a graph
- Shows the network traffic in a table

## Usage

Run the following command to start the network monitor on WEB:

```bash
streamlit run main.py -- --web
```

Run the following command to start the network monitor on DESKTOP:

```bash
python main.py
```

Run the following command to start the network monitor on CLI:

```bash
python main.py --cli
```

---

### Compile application with PyInstaller

Run the following command to compile the application with PyInstaller:

```bash
pyinstaller --onefile --name=NetMonitor --additional-hooks-dir=hooks main.py
```

For Linux, you may need to give the executable permission to the compiled file:

```bash
sudo chmod +x dist/NetMonitor
```

If you want the application to work without a black screen in Tkinter or Streamlit

```bash
pyinstaller --onefile --windowed --name=NetMonitor --additional-hooks-dir=hooks main.py
```
this will make the application run without a black screen.

If you want to compile the application with an icon, you can use the following command:

```bash
pyinstaller --onefile --windowed --name=NetMonitor --icon=icon.ico --additional-hooks-dir=hooks main.py
```

