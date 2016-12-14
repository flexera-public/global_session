describe 'Global Session IDs' do
  context 'when generated using right_support' do
    it 'has at least 50% unpredictable characters' do
      uuids = []
      pos_to_freq = {}

      1_000.times do
        uuid = RightSupport::Data::UUID.generate
        uuid.gsub!(/[^0-9a-fA-F]/, '')
        uuids << uuid
      end

      uuids.each do |uuid|
        pos = 0
        uuid.each_char do |char|
          pos_to_freq[pos] ||= {}
          pos_to_freq[pos][char] ||= 0
          pos_to_freq[pos][char] += 1
          pos += 1
        end
      end

      predictable_pos = 0
      total_pos       = 0

      pos_to_freq.each_pair do |pos, frequencies|
        n    = frequencies.size.to_f
        total  = frequencies.values.inject(0) { |x, v| x+v }.to_f
        mean = total / n

        sum_diff_sq = 0.0
        frequencies.each_pair do |char, count|
          sum_diff_sq += (count - mean)**2
        end
        var = (1 / n) * sum_diff_sq
        std_dev = Math.sqrt(var)

        predictable_pos += 1 if std_dev == 0.0
        total_pos += 1
      end

      # Less than half of the character positions should be predictable
      expect((predictable_pos.to_f / total_pos.to_f)).to be <= 0.5
    end
  end
end
