import { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { BarChart, PieChart, LineChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';

echarts.use([BarChart, PieChart, LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer]);

export type ChartOption = echarts.EChartsCoreOption;

/** Envoltorio de ECharts (solo se cargan los módulos usados para reducir el bundle) */
export function Chart({ option, height = 260, onClick }: { option: ChartOption; height?: number; onClick?: (p: { name: string; seriesName?: string }) => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    inst.current = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    const ro = new ResizeObserver(() => inst.current?.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      inst.current?.dispose();
    };
  }, []);

  useEffect(() => {
    inst.current?.setOption(
      {
        backgroundColor: 'transparent',
        textStyle: { color: '#94a3b8', fontFamily: 'inherit' },
        tooltip: { backgroundColor: '#0f1729', borderColor: '#2b3a5c', textStyle: { color: '#e2e8f0' } },
        ...option,
      },
      true,
    );
  }, [option]);

  useEffect(() => {
    if (!inst.current || !onClick) return;
    const handler = (p: unknown) => onClick(p as { name: string; seriesName?: string });
    inst.current.on('click', handler);
    return () => {
      inst.current?.off('click', handler);
    };
  }, [onClick]);

  return <div ref={ref} style={{ height, width: '100%' }} />;
}

export const axisStyle = {
  axisLine: { lineStyle: { color: '#2b3a5c' } },
  axisLabel: { color: '#94a3b8', fontSize: 11 },
  splitLine: { lineStyle: { color: '#1e2a44' } },
};
