require File.expand_path(File.join(File.dirname(__FILE__), '..' , 'spec_helper'))

describe GlobalSession::Configuration do
  include SpecHelper

  let(:config_hash) do
    {'common'=>{'attributes' => {'signed'=>['user']}, 'cookie' => {'name' => 'xyzzy'}, 'timeout' => 60}}
  end

  context '#initialize' do
    it 'accepts a Hash' do
      expect(described_class.new(config_hash, 'test')).to be_a(described_class)
    end

    it 'accepts a YAML file location' do
      f = Tempfile.new('global_session-spec')
      f.write(YAML.dump(config_hash))
      f.close
      expect(described_class.new(f.path, 'test')).to be_a(described_class)
      f.unlink
    end

    it 'validates the configuration' do
      expect { described_class.new({}, 'test') }.to raise_error(GlobalSession::MissingConfiguration)
    end

    context 'given a non-Hash, non-extant-file parameter' do
      it 'raises MissingConfiguration' do
        expect { described_class.new('/tmp/does_not_exist', 'test') }.to raise_error(GlobalSession::MissingConfiguration)
      end
    end

    context 'given a YAML file that contains something other than a Hash' do
      it 'raises TypeError' do
        f = Tempfile.new('global_session-spec')
        f.write(YAML.dump([1,2,3,4,5]))
        f.close
        expect { described_class.new(f.path, 'test') }.to raise_error(TypeError)
        f.unlink
      end
    end
  end

  context '#validate' do
    it 'validates presence of attributes/signed' do
      config_hash['common']['attributes'].delete('signed')
      expect { described_class.new(config_hash, 'test') }.to raise_error(GlobalSession::MissingConfiguration)
    end

    it 'validates presence of cookie/name' do
      config_hash['common']['cookie'].delete('name')
      expect { described_class.new(config_hash, 'test') }.to raise_error(GlobalSession::MissingConfiguration)
    end

    it 'validates presence of timeout' do
      config_hash['common'].delete('timeout')
      expect { described_class.new(config_hash, 'test') }.to raise_error(GlobalSession::MissingConfiguration)
    end
  end
end
