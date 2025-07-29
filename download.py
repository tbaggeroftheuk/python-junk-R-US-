import yt_dlp

def download_youtube(url, output_path='%(title)s.%(ext)s', download_type='mp3'):
    if download_type == 'mp3':
        ydl_opts = {
            'format': 'bestaudio/best',
            'outtmpl': output_path,
            'postprocessors': [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }],
            'quiet': False,
            'no_warnings': True,
        }
    elif download_type == 'mp4':
        ydl_opts = {
            'format': 'bestvideo+bestaudio/best',
            'outtmpl': output_path,
            'merge_output_format': 'mp4',
            'quiet': False,
            'no_warnings': True,
        }
    else:
        print(f"Unsupported download type: {download_type}")
        return

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python download_yt_mp3.py <youtube_url> <mp3|mp4>")
    else:
        url = sys.argv[1]
        download_type = sys.argv[2].lower()
        download_youtube(url, download_type=download_type)

