import { useScan } from "../context/ScanContext";

export default function ScanProgressBar() {
  const { isScanActive } = useScan();
  if (!isScanActive) return null;
  return <div className="scan-progress-bar" aria-label="Scan in progress" />;
}
