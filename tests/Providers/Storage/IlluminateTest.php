<?php

/*
 * This file is part of jwTauth.
 *
 * (c) Afroware <contact@afroware.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Afroware\JwTauth\Test\Providers\Storage;

use Mockery;
use Afroware\JwTauth\Test\AbstractTestCase;
use Illuminate\Contracts\Cache\Repository;
use Afroware\JwTauth\Test\Stubs\TaggedStorage;
use Afroware\JwTauth\Providers\Storage\Illuminate as Storage;

class IlluminateTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\Illuminate\Contracts\Cache\Repository
     */
    protected $cache;

    /**
     * @var \Afroware\JwTauth\Providers\Storage\Illuminate
     */
    protected $storage;

    public function setUp()
    {
        parent::setUp();

        $this->cache = Mockery::mock(Repository::class);
        $this->storage = new Storage($this->cache);
    }

    /** @test */
    public function it_should_add_the_item_to_storage()
    {
        $this->cache->shouldReceive('put')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_storage_forever()
    {
        $this->cache->shouldReceive('forever')->with('foo', 'bar')->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_storage()
    {
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_storage()
    {
        $this->cache->shouldReceive('forget')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_items_from_storage()
    {
        $this->cache->shouldReceive('flush')->withNoArgs()->once();

        $this->storage->flush();
    }

    // Duplicate tests for tagged storage --------------------

    /**
     * Replace the storage with our one above that overrides the tag flag, and
     * define expectations for tags() method.
     *
     * @return void
     */
    private function emulateTags()
    {
        $this->storage = new TaggedStorage($this->cache);

        $this->cache->shouldReceive('tags')->with('afroware.jwT')->once()->andReturn(Mockery::self());
    }

    /** @test */
    public function it_should_add_the_item_to_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('put')->with('foo', 'bar', 10)->once();

        $this->storage->add('foo', 'bar', 10);
    }

    /** @test */
    public function it_should_add_the_item_to_tagged_storage_forever()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('forever')->with('foo', 'bar')->once();

        $this->storage->forever('foo', 'bar');
    }

    /** @test */
    public function it_should_get_an_item_from_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('get')->with('foo')->once()->andReturn(['foo' => 'bar']);

        $this->assertSame(['foo' => 'bar'], $this->storage->get('foo'));
    }

    /** @test */
    public function it_should_remove_the_item_from_tagged_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('forget')->with('foo')->once()->andReturn(true);

        $this->assertTrue($this->storage->destroy('foo'));
    }

    /** @test */
    public function it_should_remove_all_tagged_items_from_storage()
    {
        $this->emulateTags();
        $this->cache->shouldReceive('flush')->withNoArgs()->once();

        $this->storage->flush();
    }
}
