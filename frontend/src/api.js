// File Compression Component
import { useFiles } from '../config/api';

function FileCompressor() {
  const { processFiles, processing, progress, result } = useFiles();
  
  const handleCompress = async (selectedFiles) => {
    const response = await processFiles(
      selectedFiles, 
      'compress', 
      { compressLevel: 70 }
    );
    if (response.success) {
      console.log('Compressed:', response.data.url);
    }
  };
  
  return (
    <div>
      <input type="file" multiple onChange={(e) => handleCompress([...e.target.files])} />
      {processing && <progress value={progress} max={100} />}
      {result && <a href={result.url} download>Download</a>}
    </div>
  );
}
